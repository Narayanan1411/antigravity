# Network Discovery Service

This service uses real network sniffing to detect devices and replace simulated data.

## Features
- Real-time network traffic monitoring using tshark
- Automatic device detection and registration
- Consistent random device type mapping for undetected types
- Database updates for new devices
- User authentication prompts (currently auto-approve for POC)

## Configuration
- Interface: wlp1s0 (update INTERFACE variable if different)
- Requires sudo for tshark packet capture

## Usage
The service is automatically started with ./start.sh

## Notes
- Device types are consistently mapped using MAC address as seed
- New devices are automatically added to the database
- Authentication is currently auto-approved; replace prompt_user_authentication() for real user interaction
