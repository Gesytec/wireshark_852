-- ANSI/CTA-852, ISO/IEC 14908-4 protocol
-- Copyright: 	Richard T. Brown, Johnson Controls, Inc.
--				Volker Schober, Gesytec GmbH
--				Matthias Luerkens, Gesytec GmbH
--
-- This work is licensed under the terms of GPLv3 (or any later version).
--
-- initial version from 2008
--
-- V1.3, 22.10.2014
--		adapted to new Wireshark version, getBits()
--		more LON message codes
--      transaction ID in info column
-- V1.4, 25.06.2018
--		support NAT-extensions
--
-- some more ideas:
-- 		color coding: port number mismatch for source port

PACKETTYPE_DATA_PACKET                          = 0x01
PACKETTYPE_DEVICE_REGISTRATION_REQUEST          = 0x63
PACKETTYPE_DEVICE_REGISTRATION_UNSOLICITED      = 0x03
PACKETTYPE_DEVICE_REGISTRATION_SOLICITED        = 0x71
PACKETTYPE_CHANNEL_MEMBERSHIP_REQUEST           = 0x64
PACKETTYPE_CHANNEL_MEMBERSHIP                   = 0x04
PACKETTYPE_SEND_LIST_REQUEST                    = 0x66
PACKETTYPE_SEND_LIST                            = 0x06
PACKETTYPE_CHANNEL_ROUTING_REQUEST              = 0x68
PACKETTYPE_CHANNEL_ROUTING                      = 0x08
PACKETTYPE_ACKNOWLEDGE                          = 0x07
PACKETTYPE_SEGMENT                              = 0x7F
PACKETTYPE_STATUS_HEALTH_STATISTICS_REQUEST     = 0x60
PACKETTYPE_STATUS_HEALTH_STATISTICS_RESPONSE    = 0x70
PACKETTYPE_NAT_REQUEST                          = 0x91
PACKETTYPE_NAT_RESPONSE                         = 0xD1

packetTypeTextTable =        {  [PACKETTYPE_DATA_PACKET]                        = "Data Packet",
                                [PACKETTYPE_DEVICE_REGISTRATION_REQUEST]        = "Device Registration Request",
                                [PACKETTYPE_DEVICE_REGISTRATION_UNSOLICITED]    = "Device Registration (unsolicited)",
                                [PACKETTYPE_DEVICE_REGISTRATION_SOLICITED]      = "Device Registration (solicited)",
                                [PACKETTYPE_CHANNEL_MEMBERSHIP_REQUEST]         = "Channel Membership Request",
                                [PACKETTYPE_CHANNEL_MEMBERSHIP]                 = "Channel Membership",
                                [PACKETTYPE_SEND_LIST_REQUEST]                  = "Send List Request",
                                [PACKETTYPE_SEND_LIST]                          = "Send List",
                                [PACKETTYPE_CHANNEL_ROUTING_REQUEST]            = "Channel Routing Request",
                                [PACKETTYPE_CHANNEL_ROUTING]                    = "Channel Routing",
                                [PACKETTYPE_ACKNOWLEDGE]                        = "Acknowledge",
                                [PACKETTYPE_SEGMENT]                            = "Segment",
                                [PACKETTYPE_STATUS_HEALTH_STATISTICS_REQUEST]   = "Status/Health/Statistics Request",
                                [PACKETTYPE_STATUS_HEALTH_STATISTICS_RESPONSE]  = "Status/Health/Statistics Response",
                                [PACKETTYPE_NAT_REQUEST]   						= "NAT Request",
                                [PACKETTYPE_NAT_RESPONSE]  						= "NAT Response"    }

---------------------------------------------------------------------------------------------------------------------------------
-- DATA DISSECTORS
---------------------------------------------------------------------------------------------------------------------------------

-- function to dissect a request packet
function requestDissector(buff, pinfo, dataPacket, packetType, packetTypeString)

    dataPacket:add(buff(0,4), "DateTime                          " .. getHexString(buff(0,4) :tvb(), 4))
--    dataPacket:add(buff(0,4), "DateTime                          " .. buff(0,4):uint())

--  for count = 0, 15, 1 do
--        dataPacket:add(buff(position, 1), "count=" .. count .." getBits: (0,1)=" .. getBits(count, 0, 1) .." (1,2)=" .. getBits(count, 1, 2) .." (2,3)=" .. getBits(count, 2, 3) .." (3,4)=" .. getBits(count, 3, 4) .." (1,1)=" .. getBits(count, 1, 1) .." (2,1)=" .. getBits(count, 2, 1) .." (3,1)=" .. getBits(count, 3, 1) .." (4,1)=" .. getBits(count, 4, 1))
--  end

    local reasonByte = buff(4,1):uint()

    local reason = ""  --getBits(reasonByte, 1, 2)

    if (getBits(reasonByte, 1, 2) == 0) then
        reason = reason .. "Normal request "
    elseif (getBits(reasonByte, 1, 2) == 1) then
        reason = reason .. "Verify "
		packetTypeString = packetTypeString .. " Verify"
    else
        reason = reason .. "UNKNOWN REQUEST "
    end

    local requestAll = ""
    if (getBits(reasonByte, 2, 1) == 1) then
        reason = reason .. "all, "
    else
        reason = reason .. "one, "
    end

    local copyClear = ""
    if (getBits(reasonByte, 3, 1) == 1) then
        reason = reason .. "move "
    else
        reason = reason .. "copy "
    end

	--local packetTypeString = packetTypeTextTable[packetType]
	packetTypeString = packetTypeString ..  " " .. buff(5,2):uint() .. ":" ..  buff(7,1):uint()
	pinfo.cols.info = packetTypeString
	--reason = pinfo.cols.info + " test"
	--pinfo.cols.info =reason;
    dataPacket:add(buff(4,1), "Reason                            " .. getHexString(buff(4,1) :tvb(), 1).. reason)
    dataPacket:add(buff(5,2), "Request ID                        " .. buff(5,2):uint())
    dataPacket:add(buff(7,1), "Segment ID                        " .. buff(7,1):uint())

    dataPacket:add(buff(8,4), "Since DateTime                    " .. getHexString(buff(8,4) :tvb(), 4))
--    dataPacket:add(buff(8,4), "Since DateTime                    " .. buff(8,4):uint())

    if (packetType == PACKETTYPE_CHANNEL_ROUTING_REQUEST) then
        dataPacket:add(buff(12,4), "IP Unicast Address                " .. buff(12,1):uint() .. "." .. buff(13,1):uint() .. "." .. buff(14,1):uint() .. "." .. buff(15,1):uint())

        if (dataLength > 16) then
            dataPacket:add(buff(16,2), "IP Unicast Port                   " .. buff(16,2):uint())
            dataPacket:add(buff(18,2), "MBZ                               " .. buff(18,2):uint())
        end
    else
        dataPacket:add(buff(12,4), "MBZ                               " .. buff(12,4):uint())
    end
end



-- function to dissect an acknowledge packet
function ackDissector(buff, pinfo, dataPacket, packetType)
    ACK_OK              = 0
    ACK_FIXED           = 1
    ACK_BAD_MESSAGE     = 2
    ACK_CANT_COMPLY     = 3
    ACK_DEVICE_REFUSED  = 4
    ACK_NOT_SUPPORTED   = 5
    ackTypeText = { [0] = "OK", "Fixed", "Bad message", "Cannot comply", "Device Refused", "Not supported"}


    dataPacket:add(buff(0,4), "DateTime                          " .. getHexString(buff(0,4) :tvb(), 4))
--    dataPacket:add(buff(0,4), "DateTime                          " .. buff(0,4):uint())

    local ackType = buff(4,1):uint()
    local ackTypeString = "unknown"

    if ((ackType >= ACK_OK) and (ackType <= ACK_NOT_SUPPORTED)) then
        ackTypeString = ackTypeText[ackType]
    end

    dataPacket:add(buff(4,1), "ACK Type                          " .. ackTypeString .. " (" .. buff(4,1):uint() .. ")")
    dataPacket:add(buff(5,2), "Request ID                        " .. buff(5,2):uint())
    dataPacket:add(buff(7,1), "Segment ID                        " .. buff(7,1):uint())
end


-- function to dissect an segment packet
function segmentDissector(buff, pinfo, dataPacket, packetType, packetTypeString)
    dataPacket:add(buff(0,4), "DateTime                          " .. getHexString(buff(0,4) :tvb(), 4))

	packetTypeString = packetTypeString ..  "                    " .. buff(5,2):uint() .. ":" ..  buff(7,1):uint()

    local FlagsByte = buff(4,1):uint()
	local Flags = ""
	
    if (getBits(FlagsByte, 7, 1) == 1) then
        Flags = Flags .. "Valid "
    end
    if (getBits(FlagsByte, 6, 1) == 1) then
        Flags = Flags .. "Last "
        packetTypeString = packetTypeString .. " Last"
    end

	pinfo.cols.info = packetTypeString

    dataPacket:add(buff(4,1), "Flags                             " .. Flags .. " (" .. buff(4,1):uint() .. ")")
    dataPacket:add(buff(5,2), "Request ID                        " .. buff(5,2):uint())
    dataPacket:add(buff(7,1), "Segment ID                        " .. buff(7,1):uint())
end


-- function to dissect a device registration packet
function deviceRegDissector(buff, pinfo, dataPacket, packetType)
    dataPacket:add(buff(0,4), "DateTime                          " .. getHexString(buff(0,4) :tvb(), 4))
--    dataPacket:add(buff(0,4), "DateTime                          " .. buff(0,4):uint())

    local int ipFlags    = buff(4,1):uint()
    if (getBits(ipFlags, 0, 1) == 1) then
        udpSupported = "UDP Supported "
    else
        udpSupported = ""
    end
    if (getBits(ipFlags, 1, 1) == 1) then
        tcpSupported = "TCP Supported "
    else
        tcpSupported = ""
    end
    if (getBits(ipFlags, 2, 1) == 1) then
        multicastSupported = "multi-cast supported "
    else
        multicastSupported = ""
    end

    local RouterType = buff(5,1):uint()
    if (RouterType == 0) then
        CNRouterType = "Configured"
    elseif (RouterType == 1) then
        CNRouterType = "Learning"
    elseif (RouterType == 2) then
        CNRouterType = "Bridge"
    elseif (RouterType == 3) then
        CNRouterType = "Repeater"
    else
        CNRouterType = ""
    end

    local cnFlags    = buff(6,1):uint()
    if (getBits(cnFlags, 0, 1) == 1) then
        WantsAllBroadcasts = "Wants All Broadcasts "
    else
        WantsAllBroadcasts = ""
    end
    if (getBits(cnFlags, 1, 1) == 1) then
        SecuritySupported = "Security Supported "
    else
        SecuritySupported = ""
    end

    local NodeType = buff(7,1):uint()
    if (NodeType == 1) then
        CNNodeType = "Non-IP channel to IP channel Router"
    elseif (NodeType == 2) then
        CNNodeType = "IP channel Node"
    elseif (NodeType == 3) then
        CNNodeType = "IP channel Proxy"
    elseif (NodeType == 4) then
        CNNodeType = "IP channel to IP channel Router"
    else
        CNNodeType = ""
    end


--    dataPacket:add(buff(4,1), "IP Flags                          " .. udpSupported .. tcpSupported .. multicastSupported .. "(" .. buff(4,1):uint() .. ")")
    dataPacket:add(buff(4,1), "IP Flags                          " .. getHexString(buff(4,1):tvb(), 1) .. udpSupported .. tcpSupported .. multicastSupported)
    dataPacket:add(buff(5,1), "CN Router Type                    " .. getHexString(buff(5,1):tvb(), 1) .. CNRouterType)
    dataPacket:add(buff(6,1), "CN Flags                          " .. getHexString(buff(6,1):tvb(), 1) .. WantsAllBroadcasts .. SecuritySupported)
    dataPacket:add(buff(7,1), "Node Type                         " .. getHexString(buff(7,1):tvb(), 1) .. CNNodeType)

    local mcAddressCount = buff(8,1):uint()
    dataPacket:add(buff(8,1), "Mc_Address Count                  " .. buff(8,1):uint())
    dataPacket:add(buff(9,1), "MBZ                               " .. buff(9,1):uint())
    dataPacket:add(buff(10,2), "Channel Timeout                   " .. buff(10,2):uint())

    local uniqueIdBytes = buff(12,2):uint()
    dataPacket:add(buff(12,2), "Total Unique ID Bytes             " .. buff(12,2):uint())
    dataPacket:add(buff(14,2), "IP Unicast Port                   " .. buff(14,2):uint())

    dataPacket:add(buff(16,4), "IP Unicast Address                " .. buff(16,1):uint() .. "." .. buff(17,1):uint() .. "." .. buff(18,1):uint() .. "." .. buff(19,1):uint())

    dataPacket:add(buff(20,4), "Channel Membership DateTime       " .. getHexString(buff(20,4) :tvb(), 4))
--    dataPacket:add(buff(20,4), "Channel Membership DateTime       " .. buff(20,4):uint())

    dataPacket:add(buff(24,4), "Send List DateTime                " .. getHexString(buff(24,4) :tvb(), 4))
--    dataPacket:add(buff(24,4), "Send List DateTime                " .. buff(24,4):uint())

    dataPacket:add(buff(28,4), "Config Server IP Address          " .. buff(28,1):uint() .. "." .. buff(29,1):uint() .. "." .. buff(30,1):uint() .. "." .. buff(31,1):uint())

    dataPacket:add(buff(32,4), "Primary Time Server IP Address    " .. buff(32,1):uint() .. "." .. buff(33,1):uint() .. "." .. buff(34,1):uint() .. "." .. buff(35,1):uint())

    dataPacket:add(buff(36,4), "Secondary Time Server IP Address  " .. buff(36,1):uint() .. "." .. buff(37,1):uint() .. "." .. buff(38,1):uint() .. "." .. buff(39,1):uint())

    dataPacket:add(buff(40,2), "Config Server IP Port             " .. buff(40,2):uint())
    dataPacket:add(buff(42,2), "Primary Time Server IP Port       " .. buff(42,2):uint())

    dataPacket:add(buff(44,2), "Secondary Time Server IP Port     " .. buff(44,2):uint())
    dataPacket:add(buff(46,2), "MBZ                               " .. buff(46,2):uint())

    local position = 48

    if (mcAddressCount > 0) then
        for count = 0, mcAddressCount-1, 1 do
            dataPacket:add(buff(position,4),     "MultiCast IP Address              " .. buff(position,1):uint() .. "." .. buff(position + 1,1):uint() .. "." .. buff(position + 2,1):uint() .. "." .. buff(position + 3,1):uint())
            dataPacket:add(buff(position + 4,2), "Multicast IP Port                 " .. buff(position + 4,2):uint())
            --dataPacket:add(buff(position + 6,2), "MBZ                               " .. buff(position + 6,2):uint())
            position = position + 8
        end
    end

    if (uniqueIdBytes > 0) then
--        dataPacket:add(buff(position, uniqueIdBytes), "Unique ID[]                       " .. getHexString(buff(position, uniqueIdBytes):tvb(), uniqueIdBytes))
        for count = 0, uniqueIdBytes-1, 6 do
              dataPacket:add(buff(position, 6), "Unique ID[" .. count/6 .."]                      " .. getHexString(buff(position, 6):tvb(), 6))
              position = position + 6
        end
--        for count = 0, uniqueIdBytes-1, 1 do
--            dataPacket:add(buff(position + count, 1), "Unique ID[" .. count .."]                      " .. buff(position + count, 1):uint())
--        end
    end
end



-- function to print an IP address
function printIpAddress(buff, dataPacket, name)
    dataPacket:add(buff(0,4), name .. buff(0,1):uint() .. "." .. buff(1,1):uint() .. "." .. buff(2,1):uint() .. "." .. buff(3,1):uint())
end

function printIpAddressXor(buff, dataPacket, name)
    dataPacket:add(buff(0,4), name .. bit.bxor(buff(0,1):uint(), 0xFF) .. "." .. bit.bxor(buff(1,1):uint(), 0xFF) .. "." .. bit.bxor(buff(2,1):uint(), 0xFF) .. "." .. bit.bxor(buff(3,1):uint(), 0xFF))
end



function NatResponseDissector(buff, pinfo, dataPacket, packetType)
    dataPacket:add(buff(1,2), "Request ID                        " .. buff(1,2):uint())

    dataPacket:add(buff(10,2), "IP Unicast Port                   " .. bit.bxor(buff(10,2):uint(), 0xFFFF))
    printIpAddressXor(buff(12,4):tvb(), dataPacket, "NAT Address                       ")
    printIpAddressXor(buff(16,4):tvb(), dataPacket, "??? Address                       ")
end


-- function to dissect a channel routing packet
function channelRoutingDissector(buff, pinfo, dataPacket, packetType)
    dataPacket:add(buff(0,4), "DateTime                          " .. getHexString(buff(0,4) :tvb(), 4))
--    dataPacket:add(buff(0,4), "DateTime                          " .. buff(0,4):uint())

    dataPacket:add(buff(4,2), "IP Multi-cast Port                " .. buff(4,2):uint())
    dataPacket:add(buff(6,2), "IP Unicast Port                   " .. buff(6,2):uint())

    printIpAddress(buff(8,4):tvb(), dataPacket, "IP Multi-cast Address             ")

    printIpAddress(buff(12,4):tvb(), dataPacket, "IP Unicast Address                ")


    local int ipFlags    = buff(16,1):uint()
    if (getBits(ipFlags, 0, 1) == 1) then
        udpSupported = "UDP Supported "
    else
        udpSupported = ""
    end
    if (getBits(ipFlags, 1, 1) == 1) then
        tcpSupported = "TCP Supported "
    else
        tcpSupported = ""
    end
    if (getBits(ipFlags, 2, 1) == 1) then
        multicastSupported = "multi-cast supported "
    else
        multicastSupported = ""
    end

    local RouterType = buff(17,1):uint()
    if (RouterType == 0) then
        CNRouterType = "Configured"
    elseif (RouterType == 1) then
        CNRouterType = "Learning"
    elseif (RouterType == 2) then
        CNRouterType = "Bridge"
    elseif (RouterType == 3) then
        CNRouterType = "Repeater"
    else
        CNRouterType = ""
    end

    local cnFlags    = buff(18,1):uint()
    if (getBits(cnFlags, 0, 1) == 1) then
        WantsAllBroadcasts = "Wants All Broadcasts "
    else
        WantsAllBroadcasts = ""
    end
    if (getBits(cnFlags, 1, 1) == 1) then
        SecuritySupported = "Security Supported "
    else
        SecuritySupported = ""
    end

    local NodeType = buff(19,1):uint()
    if (NodeType == 1) then
        CNNodeType = "Non-IP channel to IP channel Router"
    elseif (NodeType == 2) then
        CNNodeType = "IP channel Node"
    elseif (NodeType == 3) then
        CNNodeType = "IP channel Proxy"
    elseif (NodeType == 4) then
        CNNodeType = "IP channel to IP channel Router"
    else
        CNNodeType = ""
    end


    dataPacket:add(buff(16,1), "IP Flags                          " .. getHexString(buff(16,1):tvb(), 1) .. udpSupported .. tcpSupported .. multicastSupported)
    dataPacket:add(buff(17,1), "CN Router Type                    " .. getHexString(buff(17,1):tvb(), 1) .. CNRouterType)
    dataPacket:add(buff(18,1), "CN Flags                          " .. getHexString(buff(18,1):tvb(), 1) .. WantsAllBroadcasts .. SecuritySupported)
    dataPacket:add(buff(19,1), "Node Type                         " .. getHexString(buff(19,1):tvb(), 1) .. CNNodeType)
--    dataPacket:add(buff(16,1), "IP Flags                          " .. buff(16,1):uint())
--    dataPacket:add(buff(17,1), "CN Router Type                    " .. buff(17,1):uint())
--    dataPacket:add(buff(18,1), "CN Flags                          " .. buff(18,1):uint())
--    dataPacket:add(buff(19,1), "Node Type                         " .. buff(19,1):uint())

    local uniqueIdBytes = buff(20,2):uint()
    dataPacket:add(buff(20,2), "Total Unique ID Bytes             " .. buff(20,2):uint())
    dataPacket:add(buff(22,2), "MBZ                               " .. buff(22,2):uint())

    local subnetNodes = buff(24,2):uint()/6
    dataPacket:add(buff(24,2), "Total SubnetNode Bytes            " .. buff(24,2):uint() .. " (" .. subnetNodes .. " subnet/node addresses)")
    local domains = buff(26,2):uint()/72
    dataPacket:add(buff(26,2), "Total Domain Bytes                " .. buff(26,2):uint() .. " (" .. domains .. " domain addresses)")

    local position = 28

    for count = 0, uniqueIdBytes-1, 6 do
          dataPacket:add(buff(position, 6), "Unique ID[" .. count/6 .."]                      " .. getHexString(buff(position, 6):tvb(), 6))
          position = position + 6
    end
--    for count = 0, uniqueIdBytes-1, 1 do
--        dataPacket:add(buff(position + count, 1), "Unique ID[" .. count .."]                      " .. buff(position + count, 1):uint())
--    end
--    position = position + uniqueIdBytes

    for count = 0, subnetNodes - 1, 1 do
        dataPacket:add(buff(position  ,1), "Subnet                            " .. buff(position,1):uint())
        dataPacket:add(buff(position+1,1), "Node                              " .. buff(position+1,1):uint())
        dataPacket:add(buff(position+2,2), "Domain Index                      " .. buff(position+2,2):uint())

        dataPacket:add(buff(position+4,2), "Unique ID Index                   " .. buff(position+4,2):uint())

        position = position + 6
    end

    for count = 0, domains - 1, 1 do
        dataPacket:add(buff(position, 32), "Subnet Mask[]                     " .. getHexString(buff(position, 32):tvb(), 32))
--        for count2 = 0, 31, 1 do
--            dataPacket:add(buff(position + count2, 1), "Subnet Mask[" .. count2 .."]                    " .. buff(position + count2, 1):uint())
--        end

        position = position + 32

        dataPacket:add(buff(position, 32), "Group Mask[]                      " .. getHexString(buff(position, 32):tvb(), 32))
--        for count2 = 0, 31, 1 do
--            dataPacket:add(buff(position + count2, 1), "Group Mask[" .. count2 .."]                     " .. buff(position + count2, 1):uint())
--        end

        position = position + 32

        dataPacket:add(buff(position  ,1), "Domain Length                     " .. buff(position,1):uint())
        dataPacket:add(buff(position+1,1), "MBZ                               " .. buff(position+1,1):uint())

        position = position + 2

        dataPacket:add(buff(position, 6), "Domain ID []                      " .. getHexString(buff(position, 6):tvb(), 6))
--        for count2 = 0, 5, 1 do
--            dataPacket:add(buff(position + count2, 1), "Domain ID [" .. count2 .."]                     " .. buff(position + count2, 1):uint())
--        end

        position = position + 6
    end
end


-- function to dissect a send list packet
function sendListDissector(buff, pinfo, dataPacket, packetType)
    dataPacket:add(buff(0,4), "DateTime                          " .. getHexString(buff(0,4) :tvb(), 4))
    local listSize = buff(4,1):uint()
    dataPacket:add(buff(4,1), "List Size                         " .. buff(4,1):uint())
    dataPacket:add(buff(5,3), "MBZ                               " .. buff(5,3):uint())

    local position = 8
    for count = 0, listSize-1, 1 do
        local listMember = dataPacket:add(buff(position,8), "List Member                       " .. count .. ": " ..buff(position,1):uint() .. "." .. buff(position+1,1):uint() .. "." .. buff(position+2,1):uint() .. "." .. buff(position+3,1):uint() .. ":" .. buff(position +  4,2):uint())

        printIpAddress(buff(position,4):tvb(), listMember, "IP Address                        ")

        listMember:add(buff(position +  4,2), "IP Port                           " .. buff(position +  4,2):uint())
        listMember:add(buff(position +  6,2), "MBZ                               " .. buff(position +  6,2):uint())

        position = position + 8
    end
end


-- function to dissect a channel membership packet
function channelMembershipDissector(buff, pinfo, dataPacket, packetType)
    dataPacket:add(buff(0,4), "DateTime                          " .. getHexString(buff(0,4) :tvb(), 4))
--    dataPacket:add(buff(0,4), "DateTime                          " .. buff(0,4):uint())
    dataPacket:add(buff(4,4), "Send List DateTime                " .. getHexString(buff(4,4) :tvb(), 4))
--    dataPacket:add(buff(4,4), "Send List DateTime                " .. buff(4,4):uint())
    dataPacket:add(buff(8,4), "MBZ                               " .. buff(8,4):uint())

    local listSize = buff(12,2):uint()
    dataPacket:add(buff(12,2), "List Size                         " .. buff(12,2):uint())
    dataPacket:add(buff(14,2), "MBZ                               " .. buff(14,2):uint())

    local position = 16
    for count = 0, listSize-1, 1 do
        local listMember = dataPacket:add(buff(position,12), "List Member                       " .. count .. ": " ..buff(position,1):uint() .. "." .. buff(position+1,1):uint() .. "." .. buff(position+2,1):uint() .. "." .. buff(position+3,1):uint() .. ":" .. buff(position +  4,2):uint())

        printIpAddress(buff(position,4):tvb(), listMember, "IP Unicast Address                ")

        listMember:add(buff(position +  4,2), "IP Unicast Port                   " .. buff(position +  4,2):uint())
        listMember:add(buff(position +  6,2), "MBZ                               " .. buff(position +  6,2):uint())

        listMember:add(buff(position +  8,4), "DateTime of channel routing pkt   " .. getHexString(buff(position +  8,4) :tvb(), 4))
--        listMember:add(buff(position +  8,4), "DateTime of channel routing pkt   " .. buff(position +  8,4):uint())

        position = position + 12
    end
end




-- function to extract bits

function getBits(data, firstBit, numBits)
    local firstBitVal = math.pow(2, firstBit)
    local lastBitVal  = math.pow(2, firstBit + 1 - numBits);

--    return (math.mod(data, firstBitVal * 2) - math.mod(data, lastBitVal))/lastBitVal;
--  2014-08-19 Lue, correct name is math.fmod
    return (math.fmod(data, firstBitVal * 2) - math.fmod(data, lastBitVal))/lastBitVal;
end


-- function to get hex data
hexDigitTable   = { [0]  = "0",
                    [1]  = "1",
                    [2]  = "2",
                    [3]  = "3",
                    [4]  = "4",
                    [5]  = "5",
                    [6]  = "6",
                    [7]  = "7",
                    [8]  = "8",
                    [9]  = "9",
                    [10] = "A",
                    [11] = "B",
                    [12] = "C",
                    [13] = "D",
                    [14] = "E",
                    [15] = "F"
                  }

function getHexString(buff, buffLen)
    local hexString = ""

    for index = 0, buffLen-1, 1 do
        local number = buff(index,1):uint()

        hexString = hexString .. hexDigitTable[getBits(number, 7, 4)] .. hexDigitTable[getBits(number, 3, 4)] .. " "
    end

    return hexString
end


function getHexString0(buff, buffLen)
    local hexString = ""

    for index = 0, buffLen-1, 1 do
        local number = buff(index,1):uint()

        hexString = hexString .. hexDigitTable[getBits(number, 7, 4)] .. hexDigitTable[getBits(number, 3, 4)]
    end

    return hexString
end


function getHexString0Low(buff, buffLen)
    local hexString = ""

    for index = 0, buffLen-1, 1 do
        local number = buff(index,1):uint()

        hexString = hexString .. hexDigitTable[getBits(number, 3, 4)]
    end

    return hexString
end









-- PDU dissectors
PDU_TYPE_TPDU       = 0
PDU_TYPE_SPDU       = 1
PDU_TYPE_AUTHPDU    = 2
PDU_TYPE_APDU       = 3

pduStringTable      = { [PDU_TYPE_TPDU]     = "TPDU",
                        [PDU_TYPE_SPDU]     = "SPDU",
                        [PDU_TYPE_AUTHPDU]  = "AUTHPDU",
                        [PDU_TYPE_APDU]     = "APDU"
                      }







-- Functions to dissect an APDU
APDU_CODE_QUERY_STATUS_SUCC = 49    --0x31
APDU_CODE_NV_FETCH_SUCC     = 51    --0x33

APDU_CODE_QUERY_STATUS      = 81    --0x51
APDU_CODE_PROXY             = 82    --0x52
APDU_CODE_CLEAR_STATUS      = 83    --0x53
APDU_CODE_QUERY_XCVR_STATUS = 84    --0x54

APDU_CODE_QUERY_ID          = 97    --0x61
APDU_CODE_RESPOND_TO_QUERY  = 98    --0x62
APDU_CODE_JOIN_DOMAIN       = 99    --0x63
APDU_CODE_LEAVE_DOMAIN      = 100   --0x64
APDU_CODE_UPDATE_KEY        = 101   --0x65
APDU_CODE_UPDATE_ADDRESS    = 102   --0x66
APDU_CODE_QUERY_ADDRESS     = 103   --0x67
APDU_CODE_QUERY_NV_CONFIG   = 104   --0x68
APDU_CODE_UPDATE_GROUP_ADDRESS  = 105   --0x69
APDU_CODE_QUERY_DOMAIN      = 106   --0x6A
APDU_CODE_UPDATE_NV_CONFIG  = 107   --0x6B
APDU_CODE_SET_NODE_MODE     = 108   --0x6C
APDU_CODE_READ_MEMORY       = 109   --0x6D
APDU_CODE_WRITE_MEMORY      = 110   --0x6E
APDU_CODE_CS_RECALCULATE    = 111   --0x6F

APDU_CODE_WINK              = 112   --0x70
APDU_CODE_MEMORY_REFRESH    = 113   --0x71
APDU_CODE_QUERY_SNVT        = 114   --0x72
APDU_CODE_NV_FETCH          = 115   --0x73
APDU_CODE_DEVICE_ESCAPE     = 125   --0x7D

APDU_CODE_RTR_FAR_SIDE_ESC  = 126   --0x7E
APDU_CODE_SERVICE_PIN       = 127   --0x7F

apduCodeStringTable = { [APDU_CODE_QUERY_STATUS_SUCC]   = "Query Status success",
                        [APDU_CODE_NV_FETCH_SUCC]       = "NV Fetch success",

                        [APDU_CODE_QUERY_STATUS]        = "Query Status",
                        [APDU_CODE_PROXY]               = "Proxy",

                        [APDU_CODE_QUERY_ID]            = "Query ID",
                        [APDU_CODE_RESPOND_TO_QUERY]    = "Respond To Query",
                        [APDU_CODE_JOIN_DOMAIN]         = "Join Domain",

						[APDU_CODE_LEAVE_DOMAIN]      	= "Leave Domain",
						[APDU_CODE_UPDATE_KEY]        	= "Update Key",
						[APDU_CODE_UPDATE_ADDRESS]    	= "Update Address",
						[APDU_CODE_QUERY_ADDRESS]     	= "Query Address",
						[APDU_CODE_QUERY_NV_CONFIG]   	= "Query NV Config",
						[APDU_CODE_UPDATE_GROUP_ADDRESS]  = "Update Group Address",
						[APDU_CODE_QUERY_DOMAIN]      	= "Query Domain",
						[APDU_CODE_UPDATE_NV_CONFIG ] 	= "Update NV Config",
						
                        [APDU_CODE_SET_NODE_MODE]       = "Set Node Mode",
                        [APDU_CODE_READ_MEMORY]         = "Read Memory",
                        [APDU_CODE_WRITE_MEMORY]        = "Write Memory",
                        [APDU_CODE_CS_RECALCULATE]      = "Checksum Memory",

                        [APDU_CODE_WINK]            	= "Wink",
                        [APDU_CODE_MEMORY_REFRESH]      = "Memory Refresh",
                        [APDU_CODE_QUERY_SNVT]          = "Query SNVT",
                        [APDU_CODE_NV_FETCH]            = "NV Fetch",

                        [APDU_CODE_DEVICE_ESCAPE]       = "Device Escape",
                        [APDU_CODE_RTR_FAR_SIDE_ESC]    = "Rtr Far Side Escape",
                        [APDU_CODE_SERVICE_PIN]         = "Service Pin"
                      }

function nvApduDissector(buff, pinfo, parentPdu, packetType, addressString)
    local directionOut  = getBits(buff(0,1):uint(), 6, 1)
    local directionStringTable = { [0] = "input", [1] = "output" }
    local selector      = buff(0,2)

        selector[0] = selector[0] - 128

    local apdu          = parentPdu:add(buff(0, buff:len()), "APDU (NV)      " .. directionStringTable[directionOut] .. " " .. getHexString(selector, 2))
end

function genericApduDissector(buff, pinfo, parentPdu, packetType, addressString)
    local typeString = apduCodeStringTable[buff(0,1):uint()]

    if (typeString == nil) then
        typeString = "UNKNOWN"
    end

    local code = getBits(buff(0,1):uint(), 5, 6)
    local apdu = parentPdu:add(buff(0, buff:len()), "APDU (generic) " .. "code " .. code)

--    pinfo.cols.info = addressString .. " " .. getHexString(buff(0,1):tvb(), 1) .. " " .. typeString
    pinfo.cols.info = addressString .. " " .. getHexString(buff(0,1):tvb(), 1) .. " "
end

function nmApduDissector(buff, pinfo, parentPdu, packetType, addressString)
    local typeString = apduCodeStringTable[buff(0,1):uint()]

    if (typeString == nil) then
        typeString = "UNKNOWN"
    end

    local apdu = parentPdu:add(buff(0, buff:len()), "APDU (NetMgt)  " .. getHexString(buff(0,1):tvb(), 1) .. " " .. typeString)
    pinfo.cols.info = addressString .. " " .. getHexString(buff(0,1):tvb(), 1) .. " " .. typeString
end

function diagApduDissector(buff, pinfo, parentPdu, packetType, addressString)
    local typeString = apduCodeStringTable[buff(0,1):uint()]

    if (typeString == nil) then
        typeString = "UNKNOWN"
    end

    local apdu = parentPdu:add(buff(0, buff:len()), "APDU (Diag)    " .. getHexString(buff(0,1):tvb(), 1) .. " " .. typeString)
    pinfo.cols.info = addressString .. " " .. getHexString(buff(0,1):tvb(), 1) .. " " .. typeString
end

function foreignApduDissector(buff, pinfo, parentPdu, packetType, addressString)
    local code = getBits(buff(0,1):uint(), 3, 4)
    local apdu = parentPdu:add(buff(0, buff:len()), "APDU (foreign) " .. "code " .. code)
end

function apduDissector(buff, pinfo, parentPdu, packetType, addressString)
    local destType = buff(0,1):uint()

    if (getBits(destType, 7, 1) == 1) then
        nvApduDissector(buff, pinfo, parentPdu, packetType, addressString)
    else
        if (getBits(destType, 6, 1) == 0) then
            genericApduDissector(buff, pinfo, parentPdu, packetType, addressString)
        else
            if (getBits(destType, 5, 1) == 1) then
                nmApduDissector(buff, pinfo, parentPdu, packetType, addressString)
            else
                if (getBits(destType, 4, 1) == 1) then
                    diagApduDissector(buff, pinfo, parentPdu, packetType, addressString)
                else
                    foreignApduDissector(buff, pinfo, parentPdu, packetType, addressString)
                end
            end
        end
    end
end





-- Functions to dissect a TPDU
TPDU_TYPE_ACKD      = 0
TPDU_TYPE_UNACK_RPT = 1
TPDU_TYPE_ACK       = 2
TPDU_TYPE_REMINDER  = 4
TPDU_TYPE_REM_MSG   = 5

tpduTypeStringTable = { [TPDU_TYPE_ACKD     ]   = "Ackd",
                        [TPDU_TYPE_UNACK_RPT]   = "Unack-Rpt",
                        [TPDU_TYPE_ACK      ]   = "Ack",
                        [TPDU_TYPE_REMINDER ]   = "Rem",
                        [TPDU_TYPE_REM_MSG  ]   = "Rem/Msg"
                      }
tpduDissectorTable  = { [TPDU_TYPE_ACKD     ]   = apduDissector,
                        [TPDU_TYPE_UNACK_RPT]   = apduDissector,
                        --[TPDU_TYPE_ACK      ]   = apduDissector,
                        --[TPDU_TYPE_REMINDER ]   = ,
                        --[TPDU_TYPE_REM_MSG  ]   =
                      }

function tpduDissector(buff, pinfo, npdu, packetType, addressString)
    local tpdu = npdu:add(buff(0, buff:len()), "TPDU");
    local header = buff(0,1):uint()
    local tpduType = getBits(header, 6, 3)
    local tpduTypeString = tpduTypeStringTable[tpduType];

    tpdu:add(buff(0,1), "Auth                              " .. getBits(header, 7, 1))
    tpdu:add(buff(0,1), "TPDUtype                          " .. tpduTypeString)
    tpdu:add(buff(0,1), "Transaction #                     " .. getBits(header, 3, 4))

    local tpduContentDissector = tpduDissectorTable[tpduType]

    if (tpduContentDissector ~= nil) then
        tpduContentDissector(buff(1, buff:len() - 1):tvb(), pinfo, tpdu, packetType, addressString .. " " .. tpduTypeString)
    else
        pinfo.cols.info = addressString .. " " .. tpduTypeString
--        pinfo.cols.info = addressString .. " " .. tpduTypeString .. " " .. getHexString(buff(0,1):tvb(), 1)
        tpdu:add(buff(1, buff:len() -1), "NO DISSECTOR AVAILABLE 1")
--        tpdu:add(buff(1, buff:len() -1), "Data[]  " .. getHexString(buff(1, buff:len() -1):tvb(), buff:len()))
    end
end




-- Function to dissect an SPDU
SPDU_TYPE_REQUEST   = 0
SPDU_TYPE_RESPONSE  = 2
SPDU_TYPE_REMINDER  = 4
SPDU_TYPE_REM_MSG   = 5

spduTypeStringTable = { [SPDU_TYPE_REQUEST ]    = "Request",
                        [SPDU_TYPE_RESPONSE]    = "Response",
                        [SPDU_TYPE_REMINDER]    = "Reminder",
                        [SPDU_TYPE_REM_MSG ]    = "Rem/Msg"
                      }

function spduDissector(buff, pinfo, npdu, packetType, addressString)
    local spdu = npdu:add(buff(0, buff:len()), "SPDU");
    local header = buff(0,1):uint()
    local spduTypeString = spduTypeStringTable[getBits(header, 6, 3)]

    spdu:add(buff(0,1), "Auth                              " .. getBits(header, 7, 1))
    spdu:add(buff(0,1), "SPDUtype                          " .. spduTypeString)
    spdu:add(buff(0,1), "Transaction #                     " .. getBits(header, 3, 4))

    apduDissector(buff(1, buff:len() - 1):tvb(), pinfo, spdu, packetType, addressString .. " " .. spduTypeString)
end




pduDissectorTable   = { [PDU_TYPE_TPDU]     = tpduDissector,
                        [PDU_TYPE_SPDU]     = spduDissector,
                        --[PDU_TYPE_AUTHPDU]  = ,
                        [PDU_TYPE_APDU]     = apduDissector
                      }





-- function to dissect the source address
function sourceAddressDissector(buff, pinfo, npdu)
    local srcSubnet = buff(1,1):uint();
    local srcNode   = buff(2,1):uint();
    local addressString = "[" .. srcSubnet .. "/" .. getBits(srcNode, 6, 7) .. "]"
    local sourceAddress = npdu:add(buff(1,2), "Src Address ".. addressString)

    if (srcNode >= 128) then
        srcNode = srcNode - 128
    end

    sourceAddress:add(buff(1,1), "Subnet                            " .. srcSubnet)
    sourceAddress:add(buff(2,1), "Node                              " .. srcNode)

    return addressString
end




function enclosedPduDissector(buff, pinfo, npdu, packetType, domainLength, addressString, offset)
    local pduDissector = pduDissectorTable[getBits(buff(0,1):uint(), 5, 2)]

    addressString = getHexString0Low(buff(offset + domainLength, 1):tvb(), 1) .. " '" .. getHexString0(buff(offset, domainLength):tvb(), domainLength) .. "' " .. addressString
    if (pduDissector ~= nil) then
        pduDissector(buff(offset + domainLength, buff:len() - (offset + domainLength)):tvb(), pinfo, npdu, packetType, addressString)
    else
        npdu:add(buff(offset + domainLength, buff:len() - (offset + domainLength)), "NO DISSECTOR AVAILABLE 2")
    end
end

-- function to dissect a subnet broadcast address
function subnetBroadcastDissector(buff, pinfo, npdu, packetType, domainLength)
    npdu:add(buff(4, domainLength), "Domain " .. getHexString0(buff(4, domainLength):tvb(), domainLength))

    local sourceAddressString = sourceAddressDissector(buff, pinfo, npdu)
    local dstSubnet = buff(3,1):uint();
    local destAddressString

    if (dstSubnet ~= 0) then
        destAddressString = "[" .. dstSubnet .. "]"
    else
        destAddressString = "[DOMAIN]"
    end

    local destAddress = npdu:add(buff(3,1), "Dst Address DS bdcast " .. destAddressString)

    destAddress:add(buff(3,1), "Subnet                            " .. dstSubnet)

    enclosedPduDissector(buff, pinfo, npdu, packetType, domainLength, sourceAddressString .. "->" .. destAddressString, 4)
end


-- function to dissect a group broadcast address
function groupBroadcastDissector(buff, pinfo, npdu, packetType, domainLength)
    npdu:add(buff(4, domainLength), "Domain " .. getHexString0(buff(4, domainLength):tvb(), domainLength))

    local sourceAddressString = sourceAddressDissector(buff, pinfo, npdu)
    local dstGroup = buff(3,1):uint();
    local destAddressString = "[" .. dstGroup .. "]"
    local destAddress = npdu:add(buff(3,1), "Dst Address Grp bdcast " .. destAddressString)

    enclosedPduDissector(buff, pinfo, npdu, packetType, domainLength, sourceAddressString .. "->" .. destAddressString, 4)
end


-- function to dissect a single node address
function singleNodeDissector(buff, pinfo, npdu, packetType, domainLength)
    local srcNode   = buff(2,1):uint();
    local dstSubnet = buff(3,1):uint();
    local dstNode   = buff(4,1):uint();
    local isGroup
    local dstLength

    -- Mask off top bit (always 1)
    dstNode = getBits(dstNode, 6, 7);

    if (srcNode >= 128) then
        srcNode = srcNode - 128
        isGroup = 0
        dstLength = 2
    else
        isGroup = 1
        dstLength = 4
    end

    npdu:add(buff(3+dstLength, domainLength), "Domain " .. getHexString0(buff(3+dstLength, domainLength):tvb(), domainLength))

    local sourceAddressString = sourceAddressDissector(buff, pinfo, npdu)
    local destAddressString = "[" .. dstSubnet .. "/" .. dstNode .. "]"

    if (isGroup == 1) then
        destAddressString = destAddressString .. " Grp[" .. buff(5,1):uint() .. "/" .. buff(6,1):uint() .. "]"
    end

    local destAddress = npdu:add(buff(3,dstLength), "Dst Address " .. destAddressString)

    destAddress:add(buff(3,1), "Subnet                            " .. dstSubnet)
    destAddress:add(buff(4,1), "Node                              " .. dstNode)

    if (isGroup) then
        destAddress:add(buff(5,1), "Group                             " .. buff(5,1):uint())
        destAddress:add(buff(6,1), "Group Member                      " .. buff(6,1):uint())
    end

    enclosedPduDissector(buff, pinfo, npdu, packetType, domainLength, sourceAddressString .. "->" .. destAddressString, dstLength + 3)
end


-- function to dissect a Neuron ID address
function neuronIdDissector(buff, pinfo, npdu, packetType, domainLength)
    local dstSubnet = buff(3,1):uint();

    npdu:add(buff(10, domainLength), "Domain " .. getHexString0(buff(10, domainLength):tvb(), domainLength))

    local sourceAddressString = sourceAddressDissector(buff, pinfo, npdu)

    local hexNid = getHexString0(buff(4,6):tvb(), 6)

    local destAddressString = "[" .. dstSubnet .. "/" .. hexNid .. "]"
    local destAddress = npdu:add(buff(3,7), "Dst Address NID " .. destAddressString)
        destAddress:add(buff(3,1), "Subnet                            " .. dstSubnet)
        destAddress:add(buff(4,6), "Neuron ID                         " .. hexNid)

    enclosedPduDissector(buff, pinfo, npdu, packetType, domainLength, sourceAddressString .. "->" .. destAddressString, 10)
end




-- function to dissect a data packet

ADDR_FMT_SUBNET_BDCST   = 0
ADDR_FMT_GROUP_BDCST    = 1
ADDR_FMT_SINGLE_NODE    = 2
ADDR_FMT_NID            = 3

addrFormatStringTable = {   [ADDR_FMT_SUBNET_BDCST] = "Subnet Broadcast",
                            [ADDR_FMT_GROUP_BDCST]  = "Group Broadcast",
                            [ADDR_FMT_SINGLE_NODE]  = "Single Node",
                            [ADDR_FMT_NID]          = "Neuron ID"
                        }

addrFormatDissectorTable =  {   [ADDR_FMT_SUBNET_BDCST] = subnetBroadcastDissector,
                                --[ADDR_FMT_GROUP_BDCST]  = groupBroadcastDissector,
                                [ADDR_FMT_SINGLE_NODE]  = singleNodeDissector,
                                [ADDR_FMT_NID]          = neuronIdDissector
                            }

domainLengthDecodeTable = { [0] = 0,
                            [1] = 1,
                            [2] = 3,
                            [3] = 6
                          }

function dataPacketDissector(buff, pinfo, dataPacket, packetType)
    local networkHeader     = dataPacket:add(buff(0,1), "L2 Header");
    local l2Header = buff(0,1):uint()

        networkHeader:add(buff(0,1), "Priority                          " .. getBits(l2Header, 7, 1))
        networkHeader:add(buff(0,1), "Alternate Path                    " .. getBits(l2Header, 6, 1))
        networkHeader:add(buff(0,1), "Delta BL (backlog increment)      " .. getBits(l2Header, 5, 6))

    local offsetToCrc = buff:len() - 2

    local npdu = dataPacket:add(buff(1, offsetToCrc - 1), "NPDU")
    local header = npdu:add(buff(1,1), "Header")
    local npduHeader1 = buff(1,1):uint();

        header:add(buff(1, 1), "Version                           " .. getBits(npduHeader1, 7, 2))
        header:add(buff(1, 1), "PDU Format                        " .. pduStringTable[getBits(npduHeader1, 5, 2)])

    local addrFormat        = getBits(npduHeader1, 3, 2)
    local addrFormatString  = addrFormatStringTable[addrFormat]

        if (addrFormatString ~= nil) then
            header:add(buff(1, 1), "Addr Format                       " .. addrFormatString)
        else
            header:add(buff(1, 1), "Unknown Addr Format               ")
        end

    local domainLength = domainLengthDecodeTable[getBits(npduHeader1, 1, 2)]

        header:add(buff(1,1), "Domain Length                     " .. domainLength)

    local addrFormatDissector = addrFormatDissectorTable[addrFormat]

        if (addrFormatDissector ~= nil) then
            addrFormatDissector(buff(1, offsetToCrc - 1):tvb(), pinfo, npdu, packetType, domainLength)
        else
            npdu:add(buff(1, offsetToCrc - 1), "NO DISSECTOR AVAILABLE 3")
        end

        dataPacket:add(buff(offsetToCrc,2), "CRC                               " .. getHexString0(buff(offsetToCrc,2) :tvb(), 2))
--        dataPacket:add(buff(offsetToCrc,2), "CRC                               " .. buff(offsetToCrc,2):uint())
end

---------------------------------------------------------------------------------------------------------------------------------
-- Dissector Function Table
---------------------------------------------------------------------------------------------------------------------------------

dataDissectorFunctionTable = {  [PACKETTYPE_DATA_PACKET]                        = dataPacketDissector,
                                [PACKETTYPE_DEVICE_REGISTRATION_REQUEST]        = requestDissector,
                                [PACKETTYPE_DEVICE_REGISTRATION_UNSOLICITED]    = deviceRegDissector,
                                [PACKETTYPE_DEVICE_REGISTRATION_SOLICITED]      = deviceRegDissector,
                                [PACKETTYPE_CHANNEL_MEMBERSHIP_REQUEST]         = requestDissector,
                                [PACKETTYPE_CHANNEL_MEMBERSHIP]                 = channelMembershipDissector,
                                [PACKETTYPE_SEND_LIST_REQUEST]                  = requestDissector,
                                [PACKETTYPE_SEND_LIST]                          = sendListDissector,
                                [PACKETTYPE_CHANNEL_ROUTING_REQUEST]            = requestDissector,
                                [PACKETTYPE_CHANNEL_ROUTING]                    = channelRoutingDissector,
                                [PACKETTYPE_ACKNOWLEDGE]                        = ackDissector,
                                [PACKETTYPE_SEGMENT]                            = segmentDissector,
                                [PACKETTYPE_STATUS_HEALTH_STATISTICS_REQUEST]   = requestDissector,
                                [PACKETTYPE_NAT_REQUEST]   						= requestDissector,
								[PACKETTYPE_NAT_RESPONSE]  						= NatResponseDissector
                                --[PACKETTYPE_STATUS_HEALTH_STATISTICS_RESPONSE]  =
                             }


---------------------------------------------------------------------------------------------------------------------------------
-- declare our protocol
---------------------------------------------------------------------------------------------------------------------------------
--                     (name,       filter name,description)
CTA_852_A_proto = Proto("852A","ANSI/CTA-852A","ANSI/CTA-852-A Protocol (LON over IP)")

-- create a function to dissect it
function CTA_852_A_proto.dissector(buffer, pinfo, tree)

    -- set name used in protocol column
    pinfo.cols.protocol = "852"
    --pinfo.cols.protocol = getHexString(buffer(22,4):tvb(), 4))  --buffer(22,2):tvb()
	--pinfo.cols.protocol = buffer(-8,4):uint()
	
    local subtree = tree:add(buffer(), "ANSI/CTA-852-A Protocol Data")
        packetLength = buffer:len()
		--packetLength = buffer(0,2)
        headerLength = 20
        local header = subtree:add(buffer(0,headerLength), "Common CN/IP Header")

            header:add(buffer(0,2),  "Data Packet Length                " .. buffer(0,2) :uint())

            -- Want to signal that we have a bad packet length
            if (packetLength ~= buffer(0,2)) then
                --dplItem:set_expert_flags(PI_MALFORMED, PI_WARN)
            end

            if (buffer(2,1) :uint() > 127) then
                header:add(buffer(2,1),  "Version (VENDOR-SPECIFIC)               " .. buffer(2,1) :uint())
            else
                header:add(buffer(2,1),  "Version                           " .. buffer(2,1) :uint())
            end

        local packetType = buffer(3,1):uint()
        local packetTypeString

        local vendorCode = buffer(6,2) :uint()

            if (vendorCode == 1 or vendorCode == 2) then
                packetTypeString = packetTypeTextTable[packetType]
				if (packetTypeString == nil) then
					packetTypeString = "Vendor-specific " .. vendorCode
				else
					packetTypeString = "Vendor " .. vendorCode .. ": " .. packetTypeString
				end
            else
				if (vendorCode == 0) then
					packetTypeString = packetTypeTextTable[packetType]
				else
					packetTypeString = "Vendor-specific"
				end
            end

            -- Make sure we have something valid
            if (packetTypeString == nil) then
                packetTypeString = "unknown"
            end

            packetTypeString = getHexString(buffer(3,1):tvb(), 1) .. packetTypeString

-- Pref.uint(label, default, descr)
-- ProtoField.uint8(abbr, [name], [base], [valuestring], [mask], [desc])
-- one of base.DEC, base.HEX or base.OCT
            header:add(buffer(3,1),  "Packet Type                       " .. packetTypeString)
--            header:add(buffer(3,1),  "Packet Type                       " .. packetTypeString .. " (" .. getHexString(buffer(3,1):tvb(), 1) .. ")")
--            header:add(buffer(3,1),  "Packet Type                       " .. packetTypeString .. " (" .. buffer(3,1) :uint() .. ")")
            pinfo.cols.info = packetTypeString
            header:add(buffer(4,1),  "Ext. Header Size                  " .. buffer(4,1) :uint())

        local extHeaderSize = buffer(4,1) :uint() * 4

        local protoFlags = buffer(5,1) :uint()
        local protoFlagsSecurity = (protoFlags / 32) %2
        local protoFlagsSecurityText = { [0] = "", "(authenticated) "}
        local protoFlagsTunnelledProtocolText = { [0] = "LON", "CEBus"}
        local protocol = protoFlagsTunnelledProtocolText[protoFlags % 32]

            if (protocol == nil) then
                protocol = "UNKNOWN PROTOCOL (" .. (protoFlags % 32):string() .. ") "
            end

            header:add(buffer(5,1),  "Protocol Flags                    " .. protocol .. protoFlagsSecurityText[protoFlagsSecurity] .. "(" .. getHexString0(buffer(5,1):tvb(), 1) .. ")")

            header:add(buffer(6,2),  "Vendor Code                       " .. vendorCode)
            header:add(buffer(8,4),  "Session ID                        " .. getHexString(buffer(8,4) :tvb(), 4))
--            header:add(buffer(8,4),  "Session ID                        " .. buffer(8,4) :uint())
            header:add(buffer(12,4), "Sequence Number                   " .. buffer(12,4):uint())
            header:add(buffer(16,4), "Time Stamp                        " .. getHexString(buffer(16,4) :tvb(), 4))
--            header:add(buffer(16,4), "Time Stamp                        " .. buffer(16,4):uint())

            if (extHeaderSize > 0) then
                local extHeader = subtree:add(buffer(headerLength,extHeaderSize), "Extended Header")
                headerLength = headerLength + extHeaderSize
--				if (extHeaderSize == 12) then
					printIpAddress(buffer(20,4):tvb(), extHeader, "IP  Address                       ")
					printIpAddress(buffer(24,4):tvb(), extHeader, "NAT Address                       ")
					extHeader:add(buffer(28,2), "Port                              " .. buffer(28,2):uint())
					extHeader:add(buffer(30,2), "MBZ                               " .. buffer(30,2):uint())
--				end
            end

            dataLength   = packetLength - headerLength 
			if (protoFlagsSecurity > 0) then
				dataLength = dataLength - 16
			end
            --dataLength   = buffer(0,2) - headerLength

        local dataPacket = subtree:add(buffer(headerLength, dataLength), "Data (" .. packetTypeString .. ")")
        local dissectorFunction = dataDissectorFunctionTable[packetType]

            if (dissectorFunction == nil) then
--                dataPacket:add(buffer(headerLength, dataLength), "NO DISSECTOR AVAILABLE 4")
                dataPacket:add(buffer(headerLength,4), "DateTime                          " .. getHexString(buffer(headerLength,4) :tvb(), 4))
                headerLength = headerLength + 4
                dataLength   = dataLength   - 4
                dataPacket:add(buffer(headerLength, dataLength), getHexString(buffer(headerLength, dataLength):tvb(), dataLength))
            else
               dissectorFunction(buffer(headerLength, dataLength):tvb(), pinfo, dataPacket, packetType, packetTypeString)
            end
end


-- load the udp.port table
udp_table = DissectorTable.get("udp.port")

-- register our protocol to handle udp port 1628/1629
udp_table:add(1628,CTA_852_A_proto)
udp_table:add(1629,CTA_852_A_proto)
