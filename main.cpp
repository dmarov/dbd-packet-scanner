#include "stdlib.h"
#include <map>
#include <iostream>
#include <fstream>
#include <string>

#if !defined(WIN32) && !defined(WINx64)
#include <in.h> // this is for using ntohs() and htons() on non-Windows OS's
#endif

#include "stdlib.h"
#include "Packet.h"
#include "EthLayer.h"
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

    std::string device_mac_address = dev->getMacAddress().toString();

    if (!dev->open())
    {
        printf("Cannot open device\n");
        exit(1);
    }

    pcpp::ProtoFilter protocolFilter(pcpp::UDP);
    dev->setFilter(protocolFilter);

    while (true) {

        pcpp::RawPacketVector packetVec;
        std::map<std::string, int> endpoints;

        dev->startCapture(packetVec);

        PCAP_SLEEP(10);

        dev->stopCapture();

        std::string max_endpoint = "";
        int cnt_max = 150;

        for (pcpp::RawPacketVector::ConstVectorIterator iter = packetVec.begin(); iter != packetVec.end(); iter++)
        {
            pcpp::Packet parsedPacket(*iter);

            pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();

            std::string packet_mac = ethLayer->getSourceMac().toString();

            if (packet_mac.compare(device_mac_address) == 0) {

                pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
                pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

                int port = ntohs(udpLayer->getUdpHeader()->portSrc);
                std::string ip_address = ipLayer->getSrcIpAddress().toString();
                std::string endpoint = ip_address + ":" + std::to_string(port);

                if (endpoints.find(endpoint) != endpoints.end()) {
                    endpoints[endpoint]++;
                } else {
                    endpoints[endpoint] = 1;
                }

            }

            for(std::map<std::string, int>::const_iterator it = endpoints.begin(); it != endpoints.end(); ++it)
            {
                if (it->second > cnt_max) {

                    cnt_max = it->second;
                    max_endpoint = it->first;
                }
            }

        }

        if (!max_endpoint.empty()) {

            std::ofstream myfile;
            std::cout << "endpoint: " << max_endpoint << " ; count: " << cnt_max << std::endl;
            myfile.open(argv[1], std::ofstream::out | std::ofstream::trunc);
            myfile << "{\"endpoint\":\"" << max_endpoint << "\"}";
            myfile.close();
        }
    }
    return 0;
}


