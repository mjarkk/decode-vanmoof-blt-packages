package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var bikeID = ""
var connectionHandle uint16
var hideChallenges, showOnlyFirstPartOfUUID bool

func main() {
	var encryptionKey, btSnoopFile string
	flag.StringVar(&btSnoopFile, "file", "", "The file you want to inspect (required)")
	flag.StringVar(&encryptionKey, "encryptionKey", "", "Your bike's encryption key (not required)")
	flag.StringVar(&bikeID, "bikeId", "", "Your bike's id (\"34 56 78 9a bc de\")")
	flag.BoolVar(&hideChallenges, "hideChallenges", false, "Hide CHALLENGE characteristics and hide their presence in write requests")
	flag.BoolVar(&showOnlyFirstPartOfUUID, "showOnlyFirstPartOfUuid", false, "Only show the first part of UUIDs")
	flag.Parse()

	exit := false
	if btSnoopFile == "" {
		printErr(`file argument not set, usage: --file "bt_snoop.log"`)
		exit = true
	}
	if bikeID != "" {
		removeCharacters := []string{" ", "-", ":"}
		for _, remove := range removeCharacters {
			bikeID = strings.ReplaceAll(bikeID, remove, "")
		}

		parsedBikeID, err := hex.DecodeString(bikeID)
		if err != nil {
			printErr(`invalid bike id, error: ` + err.Error())
			exit = true
		} else {
			bikeID = bToHex(parsedBikeID)
		}
	}
	if exit {
		os.Exit(1)
	}

	if len(encryptionKey) != 0 {
		setupCrypto(encryptionKey)
	} else {
		warn(`bike's encryption key not set, usage: --encryptionKey "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`)
	}

	snoopBytes, err := os.ReadFile(btSnoopFile)
	if err != nil {
		fatal(err.Error())
	}

	if bToHex(snoopBytes[:8]) != "62 74 73 6e 6f 6f 70 00" {
		fatal("not a btl snoop file")
	}
	snoopBytes = snoopBytes[8:]

	versionNumber := binary.BigEndian.Uint32(snoopBytes[:4])
	if versionNumber != 1 {
		fatalf("expected btl snoop file format version 1 but got %d", versionNumber)
	}
	snoopBytes = snoopBytes[4:]

	dataLinkType := binary.BigEndian.Uint32(snoopBytes[:4])
	switch dataLinkType {
	case 1001:
		// Expected
	case 1002:
		fatal("Unsupported Datalink Type: HCI UART (H4)")
	case 1003:
		fatal("Unsupported Datalink Type: HCI BSCP")
	case 1004:
		fatal("Unsupported Datalink Type: HCI Serial (H5)")
	case 1005:
		fatal("Unsupported Datalink Type: Unassigned")
	default:
		fatalf("Unsupported Datalink Type: Reserved / Unassigned (%d)", dataLinkType)
	}
	snoopBytes = snoopBytes[4:]

	var nr Nr
	for {
		nr++

		originalLength := binary.BigEndian.Uint32(snoopBytes[:4])
		includedLength := binary.BigEndian.Uint32(snoopBytes[4:8])
		// packetRecordLength := binary.BigEndian.Uint32(snoopBytes[8:12])
		// cumulativeDrops := binary.BigEndian.Uint32(snoopBytes[12:16])
		// timestampSeconds := binary.BigEndian.Uint32(snoopBytes[16:20])
		// timestampMicroseconds := binary.BigEndian.Uint32(snoopBytes[20:24])
		snoopBytes = snoopBytes[24:]

		// fmt.Println("packetRecordLength:", packetRecordLength)
		// fmt.Println("cumulativeDrops:", cumulativeDrops)
		// fmt.Println("timestampSeconds:", timestampSeconds)
		// fmt.Println("timestampMicroseconds:", timestampMicroseconds)

		data := snoopBytes[:includedLength]
		if len(data) > 0 {
			parseData(data[:originalLength], nr)
		}

		snoopBytes = snoopBytes[originalLength:]
		if len(snoopBytes) == 0 {
			break
		}
	}

	const hint = "\n  Make sure you started the bluetooth sniff before you connected your sniffed device to your bike or even have bluetooth disabled before you start the sniff"

	if connectionHandle == 0 {
		warn("It seems like we where unable to get the connection handle :^(" + hint)
	} else if len(handleToUUID) == 0 {
		warn("It seems like we where unable to get the bike's UUIDs :^(" + hint)
	}

	if bikeID == "" {
		if len(deviceMacAddressToName) > 1 {
			warn("It seems like there where multiple vanmoof bike's in your area")
			warn("  please specify the bike you want to use")
			for addr, bike := range deviceMacAddressToName {
				nameToUse := bike.Full
				if bike.Full == "" {
					nameToUse = bike.Short
				}
				warn(fmt.Sprintf(`  To use %s add this arg: --bikeId "%s"`, nameToUse, addr))
			}
		}
	}
}

func parseData(data []byte, nr Nr) {
	if data[0] == 0x3e {
		// 0x3e = event magic number
		parseEvent(data, nr)
		return
	}

	if connectionHandle == 0 {
		return
	}

	dataConnectionHandle := binary.LittleEndian.Uint16([]byte{data[0], data[1] & 0x0F /* 0F = 00001111 */})
	if dataConnectionHandle == connectionHandle {
		decodeHciAclPacket(data, nr)
	}
}

const (
	pbFlagSend     byte = 0x00
	pbFlagRec      byte = 0x20
	pbFlagContinue byte = 0x10
)

var lastUncompletedPackage []byte
var lastUncompletedPackageSize uint16

func decodeHciAclPacket(data []byte, nr Nr) {
	pbFlag := data[1] & 0x30 /* 0011 0000 */

	size := binary.LittleEndian.Uint16(data[2:4])
	data = data[4 : 4+size]

	switch pbFlag {
	case pbFlagSend:
		// ..00 .... = PB Flag: First Non-automatically Flushable Packet (0)
		// >> Probably send request
	case pbFlagRec:
		// ..10 .... = PB Flag: First Automatically Flushable Packet (2)
		// >> Probably (start of) response
	case pbFlagContinue:
		// ..01 .... .... .... = PB Flag: Continuing Fragment (1)
		// >> Probably continues the byte stream started by 0x20
		lastUncompletedPackage = append(lastUncompletedPackage, data...)
		if lastUncompletedPackageSize > uint16(len(lastUncompletedPackage)) {
			return
		}

		parseAtt(lastUncompletedPackage, nr)

		lastUncompletedPackage = nil
		lastUncompletedPackageSize = 0
		return
	default:
		// TODO support other types
		return
	}

	dataLen := binary.LittleEndian.Uint16(data[:2])
	attributeProtocol := reverse(data[2:4])
	if bToHex(attributeProtocol) != "00 04" {
		fatalf("%s expected attributeProtocol 00 04 but got %s", nr, hexStyle(attributeProtocol, 0))
	}

	if dataLen > size-4 {
		lastUncompletedPackage = data[4:]
		lastUncompletedPackageSize = dataLen
	} else {
		parseAtt(data[4:], nr)
	}
}

type HandleDetials struct {
	UUID string

	// When a ATT Find Information Method is used the followed write request to that handle are labled by wireshark as configuration and not a valud
	// This value is used to determine if the handle write request is just for configuration
	WriteSeemsToBeForConfigs bool
}

var handleToUUID = map[uint16]HandleDetials{}

var knownProperties = map[string]string{
	// SECURITY_SERVICE
	"6acc5501-e631-4069-944d-b8ca7598ad50": "CHALLENGE",
	"6acc5502-e631-4069-944d-b8ca7598ad50": "KEY_INDEX",
	"6acc5503-e631-4069-944d-b8ca7598ad50": "BACKUP_CODE",
	"6acc5505-e631-4069-944d-b8ca7598ad50": "BIKE_MESSAGE",

	// DEFENSE_SERVICE
	"6acc5521-e631-4069-944d-b8ca7598ad50": "LOCK_STATE",
	"6acc5522-e631-4069-944d-b8ca7598ad50": "UNLOCK_REQUEST",
	"6acc5523-e631-4069-944d-b8ca7598ad50": "ALARM_STATE",
	"6acc5524-e631-4069-944d-b8ca7598ad50": "ALARM_MODE",

	// MOVEMENT_SERVICE
	"6acc5531-e631-4069-944d-b8ca7598ad50": "DISTANCE",
	"6acc5532-e631-4069-944d-b8ca7598ad50": "SPEED",
	"6acc5533-e631-4069-944d-b8ca7598ad50": "UNIT_SYSTEM",
	"6acc5534-e631-4069-944d-b8ca7598ad50": "POWER_LEVEL",
	"6acc5535-e631-4069-944d-b8ca7598ad50": "SPEED_LIMIT",
	"6acc5536-e631-4069-944d-b8ca7598ad50": "E_SHIFTER_GEAR",
	"6acc5537-e631-4069-944d-b8ca7598ad50": "E_SHIFTIG_POINTS",
	"6acc5538-e631-4069-944d-b8ca7598ad50": "E_SHIFTER_MODE",

	// BIKE_INFO_SERVICE
	"6acc5541-e631-4069-944d-b8ca7598ad50": "MOTOR_BATTERY_LEVEL",
	"6acc5542-e631-4069-944d-b8ca7598ad50": "MOTOR_BATTERY_STATE",
	"6acc5543-e631-4069-944d-b8ca7598ad50": "MODULE_BATTERY_LEVEL",
	"6acc5544-e631-4069-944d-b8ca7598ad50": "MODULE_BATTERY_STATE",
	"6acc554a-e631-4069-944d-b8ca7598ad50": "BIKE_FIRMWARE_VERSION",
	"6acc554b-e631-4069-944d-b8ca7598ad50": "BLE_CHIP_FIRMWARE_VERSION",
	"6acc554c-e631-4069-944d-b8ca7598ad50": "CONTROLLER_FIRMWARE_VERSION",
	"6acc554d-e631-4069-944d-b8ca7598ad50": "PCBA_HARDWARE_VERSION",
	"6acc554e-e631-4069-944d-b8ca7598ad50": "GSM_FIRMWARE_VERSION",
	"6acc554f-e631-4069-944d-b8ca7598ad50": "E_SHIFTER_FIRMWARE_VERSION",
	"6acc5550-e631-4069-944d-b8ca7598ad50": "BATTERY_FIRMWARE_VERSION",
	"6acc5552-e631-4069-944d-b8ca7598ad50": "FRAME_NUMBER",

	// BIKE_STATE_SERVICE
	"6acc5561-e631-4069-944d-b8ca7598ad50": "MODULE_MODE",
	"6acc5562-e631-4069-944d-b8ca7598ad50": "MODULE_STATE",
	"6acc5563-e631-4069-944d-b8ca7598ad50": "ERRORS",
	"6acc5564-e631-4069-944d-b8ca7598ad50": "WHEEL_SIZE",
	"6acc5567-e631-4069-944d-b8ca7598ad50": "CLOCK",

	// SOUND_SERVICE
	"6acc5571-e631-4069-944d-b8ca7598ad50": "PLAY_SOUND",
	"6acc5572-e631-4069-944d-b8ca7598ad50": "SOUND_VOLUME",
	"6acc5574-e631-4069-944d-b8ca7598ad50": "BELL_SOUND",

	// LIGHT_SERVICE
	"6acc5581-e631-4069-944d-b8ca7598ad50": "LIGHT_MODE",
	"6acc5584-e631-4069-944d-b8ca7598ad50": "SENSOR",
}

var lastRWRequestHandle uint16

func parseAtt(data []byte, nr Nr) {
	methodMask := byte(0x3F) /* 00111111 */
	method := data[0] & methodMask
	switch method {
	case 0x05:
		// ..00 0101 = Method: Find Information Response (0x05)
		// findInformation := data[0]
		uuidFormat := data[1]
		if uuidFormat != 0x01 {
			fmt.Printf("%d unkonwn find information response uuid format %d", nr, uuidFormat)
			return
		}

		// TODO This seems like a dirty hack
		handle := binary.LittleEndian.Uint16(data[2:4])
		_, handleFound := handleToUUID[handle]
		perviouseHandleUUID, perviouseFound := handleToUUID[handle-1]
		if !handleFound && perviouseFound {
			handleToUUID[handle] = HandleDetials{UUID: perviouseHandleUUID.UUID, WriteSeemsToBeForConfigs: true}
		}
	case 0x01, 0x02, 0x03, 0x04:
		// ..00 0001 = Method: Error Response (0x01)
		// ..00 0010 = Method: Exchange MTU Request (0x02)
		// ..00 0011 = Method: Exchange MTU Response (0x03)
		// ..00 0100 = Method: Find Information Request (0x04)
		// Ignore
	case 0x12:
		// ..01 0010 = Method: Write Request (0x12)
		lastRWRequestHandle = binary.LittleEndian.Uint16(data[1:3])
		payload := data[3:]

		payloadText := hexStyle(payload, 0)
		if len(payload) != 0 && len(payload)%16 == 0 {
			if canDecrypt() {
				decrypted, err := decrypt(payload)
				if err != nil {
					fmt.Printf("%s unable to decrypt %s, error: %s\n", nr, hexStyle(data[3:], 0), err.Error())
				} else {
					payloadText = hexStyle(decrypted, hexStyleDecrypted|hexStyleContainsNonce)
				}
			} else {
				payloadText = hexStyle(payload, hexStyleUnDecrypted)
			}
		} else if len(payload) == 2 {
			uuid, found := handleToUUID[lastRWRequestHandle]
			if found && uuid.WriteSeemsToBeForConfigs {
				configMsg := fmt.Sprintf(" Probably ATT Config (Notification: %t)", payload[0]&0x01 == 0x01)
				payloadText += " " + style.String(configMsg).Foreground(nonEssentialColor).String()
			}
		}

		fmt.Printf("%s %s %s > %s\n", nr, applyMeta("Write req"), humanHandle(lastRWRequestHandle), payloadText)
	case 0x0a:
		// ..00 1010 = Method: Read Request (0x0a)
		lastRWRequestHandle = binary.LittleEndian.Uint16(data[1:3])
	case 0x0b, 0x13:
		// ..00 1011 = Method: Read Response (0x0b)
		// ..01 0011 = Method: Write Response (0x13)
		if lastRWRequestHandle == 0 {
			return
		}

		payload := data[1:]

		kind := "Read"
		if method == 0x13 {
			kind = "Write resp"
			if len(payload) == 0 {
				return
			}
		}

		uuid := handleToUUID[lastRWRequestHandle].UUID
		if hideChallenges && uuid == "6acc5501-e631-4069-944d-b8ca7598ad50" {
			return
		}

		payloadAsText := hexStyle(payload, 0)
		if len(payload) != 0 && len(payload)%16 == 0 {
			if canDecrypt() {
				decrypted, err := decrypt(payload)
				if err != nil {
					fmt.Printf("%s unable to decrypt %s, error: %s\n", nr, hexStyle(data[1:], 0), err.Error())
				} else {
					payloadAsText = hexStyle(decrypted, hexStyleDecrypted)
				}
			} else {
				payloadAsText = hexStyle(payload, hexStyleUnDecrypted)
			}
		} else if method == 0x0b && uuid == "6acc5501-e631-4069-944d-b8ca7598ad50" {
			payloadAsText = hexStyle(payload, hexStyleContainsNonce)
		}

		fmt.Printf("%s %s %s > %s\n", nr, applyMeta(kind), humanHandle(lastRWRequestHandle), payloadAsText)

		lastRWRequestHandle = 0
	case 0x08:
		// ..00 1000 = Method: Read By Type Request (0x08)
		// Ignore
	case 0x09:
		// ..00 1001 = Method: Read By Type Response (0x09)
		attributeLen := data[1]
		data = data[2:]
		for {
			// handle := binary.LittleEndian.Uint16(data[:2])
			// properties := data[2]
			characteristicValueHandle := binary.LittleEndian.Uint16(data[3:5])

			if attributeLen == 21 {
				uuid := bToUUID(data[5:21], true)
				handleToUUID[characteristicValueHandle] = HandleDetials{UUID: uuid}
			} else if attributeLen == 18 {
				// fmt.Println(nr)
				// UUID = generic access profile
			} else {
				fmt.Printf("%s unknown attribute len %d\n", nr, attributeLen)
			}

			data = data[attributeLen:]
			if len(data) == 0 {
				break
			}
		}
	case 0x10:
		// ..01 0000 = Method: Read By Group Type Request (0x10)
		// Ignore
	case 0x11:
		// ..01 0001 = Method: Read By Group Type Response (0x11)
		attributeLen := data[1]
		data = data[2:]
		for {
			// handle := binary.LittleEndian.Uint16(data[:2])
			// groupEndHandle := binary.LittleEndian.Uint16(data[2:4])

			if attributeLen == 6 {
				// UUID = generic access profile
				// fmt.Println(nr)
			} else if attributeLen == 20 {
				// uuid := bToUUID(data[4:20], true)
				// fmt.Println(handle, groupEndHandle, uuid)
			} else {
				fmt.Printf("%s unknown attribute len %d\n", nr, attributeLen)
			}

			data = data[attributeLen:]
			if len(data) == 0 {
				break
			}
		}
	case 0x1b:
		// ..01 1011 = Method: Handle Value Notification (0x1b)
		handle := binary.LittleEndian.Uint16(data[1:3])
		payload := data[3:]

		uuid := handleToUUID[handle].UUID

		payloadAsText := hexStyle(payload, 0)
		if len(payload) != 0 && len(payload)%16 == 0 {
			if canDecrypt() {
				decrypted, err := decrypt(payload)
				if err != nil {
					fmt.Printf("%s unable to decrypt %s, error: %s\n", nr, hexStyle(data[1:], 0), err.Error())
				} else {
					payloadAsText = hexStyle(decrypted, hexStyleDecrypted)
				}
			} else {
				payloadAsText = hexStyle(payload, hexStyleUnDecrypted)
			}
		} else if method == 0x0b && uuid == "6acc5501-e631-4069-944d-b8ca7598ad50" {
			payloadAsText = hexStyle(payload, hexStyleContainsNonce)
		}

		fmt.Printf("%s %s %s > %s\n", nr, applyMeta("Notify"), humanHandle(handle), payloadAsText)
	default:
		fmt.Printf("%s Unknown ATT method %s\n", nr, bToHex([]byte{method}))
	}
}

func reverse[S ~[]E, E any](s S) S {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

type DeviceNames struct {
	Short string
	Full  string
}

var deviceMacAddressToName = map[string]DeviceNames{}

func parseEvent(data []byte, nr Nr) {
	// parameterTotalLen := data[1]
	subEvent := data[2]
	switch subEvent {
	case 0x02:
		// Sub Event: LE Advertizing report (0x02)
		// nrReports := data[3]
		eventType := data[4]
		// peerAddressType := data[5]
		address := bToHex(reverse(data[6:12]))
		dataLen := data[12]
		if dataLen == 0 {
			return
		}

		hasFlags := false
		switch eventType {
		case 0x00, 0x10, 0x20, 0x60:
			// Event Type: Connectable Undirected Advertising (0x00)
			// Event Type: Unknown (0x20)
			// Event Type: Unknown (0x10)
			// Event Type: Unknown (0x60)
			hasFlags = true
		case 0x04, 0x13, 0x014, 0x24:
			// Event Type: Scan Response (0x04)
			// Event Type: Unknown (0x13)
			// Event Type: Unknown (0x14)
			// Event Type: Unknown (0x24)
			hasFlags = false
		case 0x12, 0x22, 0x23:
			// Event Type: Unknown (0x12)
			// Event Type: Unknown (0x22)
			// Event Type: Unknown (0x23)
			// These events come up in blt sniffs but are never send by vanmoof bikes (seems like)
			return
		case 0x02, 0x03:
			// Event Type: Non-Connectable Undirected Advertising (0x03)
			// Event Type: Scannable Undirected Advertising (0x02)
			// These event seem to come from devices that can't be connected to
			return
		default:
			fmt.Printf("%s Unknown advertising event type 0x%x\n", nr, eventType)
			return
		}

		data = data[13:]
		if hasFlags {
			flagsLen := data[0]
			data = data[flagsLen+1:]
		}

		deviceNameLen := data[0]
		deviceNameType := data[1]
		if deviceNameType != 0x08 && deviceNameType != 0x09 {
			return
		}
		shortDeivceName := deviceNameType == 0x08

		deviceName := string(data[2 : deviceNameLen+1])

		// Check if the device name seems like a vm bike (ES3-.....)
		if len(deviceName) < 5 {
			return
		}
		if deviceName[0] != 'E' {
			return
		}
		foundDeviceVariants := false
		for _, allowedDeviceVariant := range []byte{'S', 'X', 'A', 'V'} {
			if deviceName[1] == allowedDeviceVariant {
				foundDeviceVariants = true
				break
			}
		}
		if !foundDeviceVariants {
			return
		}

		_, err := strconv.Atoi(string(deviceName[2]))
		if err != nil {
			return
		}

		if deviceName[3] != '-' {
			return
		}

		dn := deviceMacAddressToName[address]
		if shortDeivceName {
			dn.Short = deviceName
		} else {
			dn.Full = deviceName
		}
		deviceMacAddressToName[address] = dn
	case 0x0a:
		// Sub Event: LE Enhanced Connection Complete (0x0a)

		address := bToHex(reverse(data[8:14]))

		if bikeID != "" {
			if address != bikeID {
				// This is not a package we're interested in
				return
			}
		} else {
			_, ok := deviceMacAddressToName[address]
			if !ok {
				return
			}
		}

		connectionHandle = binary.LittleEndian.Uint16(data[4:6])
	case 0x04, 0x06, 0x03:
		// Sub Event: LE Connection Update Complete (0x03)
		// Sub Event: LE Read Remote Features Complete (0x04)
		// Sub Event: LE Remote Connection Parameter Request (0x06)
		// These sub commands do not contain any vauluable information
	}
}
