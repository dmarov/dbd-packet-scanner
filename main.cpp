#include "stdlib.h"
#include <map>
#include <iostream>

#if !defined(WIN32) && !defined(WINx64)
#include <in.h> // this is for using ntohs() and htons() on non-Windows OS's
#endif

#include "stdlib.h"
#include "Packet.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "PcapLiveDeviceList.h"
#include "PlatformSpecificUtils.h"

int main(int argc, char* argv[])
{

    const std::vector<pcpp::PcapLiveDevice*>& devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    pcpp::PcapLiveDevice* dev = NULL;

    for (std::vector<pcpp::PcapLiveDevice*>::const_iterator iter = devList.begin(); iter != devList.end(); iter++)
    {
        if((*iter)->getDefaultGateway() != pcpp::IPv4Address::Zero) {

            dev = *iter;
        }
    }

    if (dev == NULL)
    {
        printf("Cannot find ethernet interface");
        exit(1);
    }

    pcpp::PcapLiveDevice::DeviceConfiguration config;

    config.mode = pcpp::PcapLiveDevice::DeviceMode::Normal;
    config.direction = pcpp::PcapLiveDevice::PcapDirection::PCPP_OUT;

    if (!dev->open(config))
    {
        printf("Cannot open device\n");
        exit(1);
    }

    pcpp::ProtoFilter protocolFilter(pcpp::UDP);
    dev->setFilter(protocolFilter);

    while (true) {

        pcpp::RawPacketVector packetVec;
        std::map<int, int> ports;

        printf("Started capture\n");

        dev->startCapture(packetVec);

        PCAP_SLEEP(10);

        dev->stopCapture();

        printf("Stoped capturing\n");

        for (pcpp::RawPacketVector::ConstVectorIterator iter = packetVec.begin(); iter != packetVec.end(); iter++)
        {
            pcpp::Packet parsedPacket(*iter);

            pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();

            int port = udpLayer->getUdpHeader()->portSrc;

            std::cout << port << std::endl;
        }
    }
    return 0;
}


