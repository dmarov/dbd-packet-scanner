#if !defined(WIN32) && !defined(WINx64)
#include <in.h> // this is for using ntohs() and htons() on non-Windows OS's
#endif
#include "stdlib.h"
#include "Packet.h"
#include "EthLayer.h"
#include "VlanLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "UdpLayer.h"
#include "DnsLayer.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "PlatformSpecificUtils.h"

#include <iostream>

static bool onPacketArrivesBlockingMode(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
    pcpp::Packet parsedPacket(packet);


    pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    /* ethLayer->setDestMac(pcpp::MacAddress("aa:bb:cc:dd:ee:ff")); */
    /* ethLayer->setSourceMac(pcpp::MacAddress("aa:bb:cc:dd:ee:ff")); */
    ipLayer->setSrcIpAddress(pcpp::IPv4Address("0.0.0.0"));
    ipLayer->setDstIpAddress(pcpp::IPv4Address("0.0.0.0"));
    parsedPacket.computeCalculateFields();

    std::cout << parsedPacket.toString() << std::endl;
    return false;
}

int main(int argc, char* argv[])
{
    //////////////// toying with device ////////////////////////////////////////////
    std::string interfaceIPAddr = "192.168.0.101";
    pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr.c_str());

    if (dev == NULL)
    {
        printf("Cannot find interface with IPv4 address of '%s'\n", interfaceIPAddr.c_str());
        exit(1);
    }


    // before capturing packets let's print some info about this interface
    printf("Interface info:\n");
    // get interface name
    printf("   Interface name:        %s\n", dev->getName());
    // get interface description
    printf("   Interface description: %s\n", dev->getDesc());
    // get interface MAC address
    printf("   MAC address:           %s\n", dev->getMacAddress().toString().c_str());
    // get default gateway for interface
    printf("   Default gateway:       %s\n", dev->getDefaultGateway().toString().c_str());
    // get interface MTU
    printf("   Interface MTU:         %d\n", dev->getMtu());
    // get DNS server if defined for this interface
    if (dev->getDnsServers().size() > 0)
        printf("   DNS server:            %s\n", dev->getDnsServers().at(0).toString().c_str());

    // open the device before start capturing/sending packets
    if (!dev->open())
    {
        printf("Cannot open device\n");
        exit(1);
    }

    pcpp::PortFilter portFilter(7778, pcpp::DST);
    pcpp::IPFilter ipFilter("18.156.244.248", pcpp::DST);
    pcpp::ProtoFilter protocolFilter(pcpp::UDP);
    pcpp::AndFilter andFilter;

    /* andFilter.addFilter(&protocolFilter); */
    /* andFilter.addFilter(&portFilter); */
    /* andFilter.addFilter(&ipFilter); */

    /* dev->setFilter(protocolFilter); */
    dev->startCaptureBlockingMode(onPacketArrivesBlockingMode, (void*)0, 100);
}
