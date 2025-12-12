#!/bin/bash

# DOS Detector Quick Launch Script for Kali Linux

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         DOS ATTACK DETECTOR - QUICK START                  ║${NC}"
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}❌ Error: Must run as root${NC}"
    echo -e "${YELLOW}Usage: sudo ./start.sh${NC}"
    exit 1
fi

# Check Python3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python3 not found!${NC}"
    exit 1
fi

# Check Scapy
echo -e "${BLUE}Checking dependencies...${NC}"
python3 -c "import scapy" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}Installing Scapy...${NC}"
    apt-get update > /dev/null 2>&1
    apt-get install -y python3-scapy > /dev/null 2>&1
    echo -e "${GREEN}✓ Scapy installed${NC}"
else
    echo -e "${GREEN}✓ Scapy already installed${NC}"
fi

echo ""
echo -e "${BLUE}Available network interfaces:${NC}"
ip link show | grep -E "^[0-9]+" | awk '{print "  - " $2}' | sed 's/:$//'

echo ""
echo -e "${YELLOW}Select interface (or press Enter for auto-detect):${NC}"
read -p "Interface: " INTERFACE

echo ""
echo -e "${GREEN}Starting DOS Attack Detector...${NC}"
echo ""

if [ -z "$INTERFACE" ]; then
    python3 monitor.py
else
    python3 monitor.py "$INTERFACE"
fi
