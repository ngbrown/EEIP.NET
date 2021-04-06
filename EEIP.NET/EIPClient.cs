using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Sres.Net.EEIP.ObjectLibrary;

namespace Sres.Net.EEIP
{
    public class EEIPClient : IDisposable
    {
        private TcpClient client;
        private NetworkStream stream;
        private uint sessionHandle;
        private uint connectionID_O_T;
        private uint connectionID_T_O;

        /// <summary>
        /// Value of IP address. The value is in big-endian format
        /// </summary>
        private uint multicastAddress;

        private ushort connectionSerialNumber;
        /// <summary>
        /// UDP-Port of the IO-Adapter - Standard is 0xAF12
        /// Received on SocketInfoItem message
        /// </summary>
        public ushort TargetUDPPort { get; private set; } = 0x08AE;
        /// <summary>
        /// UDP-Port of the Scanner - Standard is 0xAF12
        /// </summary>
        public ushort OriginatorUDPPort { get; set; } = 0x08AE;
        /// <summary>
        /// IPAddress of the Ethernet/IP Device
        /// </summary>
        private IPAddress targetIpAddress = new IPAddress(new byte[] {172, 0, 0, 1});
        /// <summary>
        /// Requested Packet Rate (RPI) in Microseconds Originator -> Target for Implicit-Messaging (Default 0x7A120 -> 500ms)
        /// </summary>
        public uint RequestedPacketRate_O_T { get; set; } = 0x7A120;      //500ms
        /// <summary>
        /// Requested Packet Rate (RPI) in Microseconds Target -> Originator for Implicit-Messaging (Default 0x7A120 -> 500ms)
        /// </summary>
        public uint RequestedPacketRate_T_O { get; set; } = 0x7A120;      //500ms
        /// <summary>
        /// "1" Indicates that multiple connections are allowed Originator -> Target for Implicit-Messaging (Default: TRUE) 
        /// </summary>
        public bool O_T_OwnerRedundant { get; set; } = true;                //For Forward Open
        /// <summary>
        /// "1" Indicates that multiple connections are allowed Target -> Originator for Implicit-Messaging (Default: TRUE) 
        /// </summary>
        public bool T_O_OwnerRedundant { get; set; } = true;                //For Forward Open
        /// <summary>
        /// With a fixed size connection, the amount of data shall be the size of specified in the "Connection Size" Parameter.
        /// With a variable size, the amount of data could be up to the size specified in the "Connection Size" Parameter
        /// Originator -> Target for Implicit Messaging (Default: True (Variable length))
        /// </summary>
        public bool O_T_VariableLength { get; set; } = true;                //For Forward Open
        /// <summary>
        /// With a fixed size connection, the amount of data shall be the size of specified in the "Connection Size" Parameter.
        /// With a variable size, the amount of data could be up to the size specified in the "Connection Size" Parameter
        /// Target -> Originator for Implicit Messaging (Default: True (Variable length))
        /// </summary>
        public bool T_O_VariableLength { get; set; } = true;                //For Forward Open
        /// <summary>
        /// The maximum size in bytes (only pure data without sequence count and 32-Bit Real Time Header (if present)) from Originator -> Target for Implicit Messaging (Default: 505)
        /// </summary>
        public ushort O_T_Length { get; set; } = 505;                //For Forward Open - Max 505
        /// <summary>
        /// The maximum size in bytes (only pure data without sequence count and 32-Bit Real Time Header (if present)) from Target -> Originator for Implicit Messaging (Default: 505)
        /// </summary>
        public ushort T_O_Length { get; set; } = 505;                //For Forward Open - Max 505
        /// <summary>
        /// Connection Type Originator -> Target for Implicit Messaging (Default: ConnectionType.Point_to_Point)
        /// </summary>
        public ConnectionType O_T_ConnectionType { get; set; } = ConnectionType.Point_to_Point;
        /// <summary>
        /// Connection Type Target -> Originator for Implicit Messaging (Default: ConnectionType.Multicast)
        /// </summary>
        public ConnectionType T_O_ConnectionType { get; set; } = ConnectionType.Multicast;
        /// <summary>
        /// Priority Originator -> Target for Implicit Messaging (Default: Priority.Scheduled)
        /// Could be: Priority.Scheduled; Priority.High; Priority.Low; Priority.Urgent
        /// </summary>
        public Priority O_T_Priority { get; set; } = Priority.Scheduled;
        /// <summary>
        /// Priority Target -> Originator for Implicit Messaging (Default: Priority.Scheduled)
        /// Could be: Priority.Scheduled; Priority.High; Priority.Low; Priority.Urgent
        /// </summary>
        public Priority T_O_Priority { get; set; } = Priority.Scheduled;
        /// <summary>
        /// Class Assembly (Consuming IO-Path - Outputs) Originator -> Target for Implicit Messaging (Default: 0x64)
        /// </summary>
        public byte O_T_InstanceID { get; set; } = 0x64;               //Ausgänge
        /// <summary>
        /// Class Assembly (Producing IO-Path - Inputs) Target -> Originator for Implicit Messaging (Default: 0x64)
        /// </summary>
        public byte T_O_InstanceID { get; set; } = 0x65;               //Eingänge
        /// <summary>
        /// Provides Access to the Class 1 Real-Time IO-Data Originator -> Target for Implicit Messaging    
        /// </summary>
        private readonly byte[] _O_T_IOData = new byte[505];   //Class 1 Real-Time IO-Data O->T   

        private readonly object _O_T_IOData_lock = new object();

        /// <summary>
        /// Provides Access to the Class 1 Real-Time IO-Data Target -> Originator for Implicit Messaging
        /// </summary>
        private readonly byte[] _T_O_IOData = new byte[505];    //Class 1 Real-Time IO-Data T->O  

        private readonly object _T_O_IOData_lock = new object();


        /// <summary>
        /// Used Real-Time Format Originator -> Target for Implicit Messaging (Default: RealTimeFormat.Header32Bit)
        /// Possible Values: RealTimeFormat.Header32Bit; RealTimeFormat.Heartbeat; RealTimeFormat.ZeroLength; RealTimeFormat.Modeless
        /// </summary>
        public RealTimeFormat O_T_RealTimeFormat { get; set; } = RealTimeFormat.Header32Bit;
        /// <summary>
        /// Used Real-Time Format Target -> Originator for Implicit Messaging (Default: RealTimeFormat.Modeless)
        /// Possible Values: RealTimeFormat.Header32Bit; RealTimeFormat.Heartbeat; RealTimeFormat.ZeroLength; RealTimeFormat.Modeless
        /// </summary>
        public RealTimeFormat T_O_RealTimeFormat { get; set; } = RealTimeFormat.Modeless;
        /// <summary>
        /// AssemblyObject for the Configuration Path in case of Implicit Messaging (Standard: 0x04)
        /// </summary>
        public byte AssemblyObjectClass { get; set; } = 0x04;
        /// <summary>
        /// ConfigurationAssemblyInstanceID is the InstanceID of the configuration Instance in the Assembly Object Class (Standard: 0x01)
        /// </summary>
        public byte ConfigurationAssemblyInstanceID { get; set; } = 0x01;
        /// <summary>
        /// Returns the Date and Time when the last Implicit Message has been received fŕom The Target Device
        /// Could be used to determine a Timeout
        /// </summary>        
        public DateTime LastReceivedImplicitMessage { get; set; }

        public bool IsSessionRegistered
        {
            get { return this.stream != null; }
        }

        public bool IsForwardOpen
        {
            get { return this.udpClientReceiveClosed == false && udpClientReceive?.Client != null; }
        }

        private void ReceiveIdentityCallback(IAsyncResult ar)
        {
            var udpState = (UdpState)ar.AsyncState;

            try
            {
                var receiveBytes = udpState.u.EndReceive(ar, ref udpState.e);
                var receiveString = Encoding.ASCII.GetString(receiveBytes);

                // EndReceive worked and we have received data and remote endpoint
                if (receiveBytes.Length > 0)
                {
                    var command = Convert.ToUInt16(receiveBytes[0]
                                                   | (receiveBytes[1] << 8));
                    if (command == 0x63)
                    {
                        receivedCipIdentities.TryAdd(Encapsulation.CIPIdentityItem.Deserialize(24, receiveBytes), 0);
                    }
                }
                var asyncResult = udpState.u.BeginReceive(ReceiveIdentityCallback, (UdpState)ar.AsyncState);
            }
            catch (Exception ex)
            {
                if (ex is ObjectDisposedException || ex is SocketException)
                {
                    // TODO: Log it as a trace here
                    return;
                }
                // Wasn't an exception we were looking for so rethrow it.
                throw;
            }
        }

        public class UdpState
        {
            public IPEndPoint e;
            public UdpClient u;
        }

        private readonly ConcurrentDictionary<Encapsulation.CIPIdentityItem, int> receivedCipIdentities = new ConcurrentDictionary<Encapsulation.CIPIdentityItem, int>();

        /// <summary>
        /// List and identify potential targets. This command shall be sent as broadcast massage using UDP.
        /// </summary>
        /// <returns><see cref="Encapsulation.CIPIdentityItem"/> contains the received informations from all devices </returns>	
        public async Task<List<Encapsulation.CIPIdentityItem>> ListIdentityAsync()
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                {
                    foreach (var ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            var mask = ip.IPv4Mask;
                            var address = ip.Address;

                            var multicastAddress = (address.GetAddressBytes()[0] | (~mask.GetAddressBytes()[0] & 0xFF)) + "." + (address.GetAddressBytes()[1] | (~mask.GetAddressBytes()[1] & 0xFF)) + "." + (address.GetAddressBytes()[2] | (~mask.GetAddressBytes()[2] & 0xFF)) + "." + (address.GetAddressBytes()[3] | (~mask.GetAddressBytes()[3] & 0xFF));

                            var sendData = new byte[24];
                            sendData[0] = 0x63; //Command for "ListIdentity"
                            var udpClient = new UdpClient();
                            var endPoint = new IPEndPoint(System.Net.IPAddress.Parse(multicastAddress), 44818);
                            await udpClient.SendAsync(sendData, sendData.Length, endPoint);

                            var s = new UdpState {e = endPoint, u = udpClient};

                            var asyncResult = udpClient.BeginReceive(ReceiveIdentityCallback, s);

                            await Task.Delay(1000);
                        }
                    }
                }
            }

            return receivedCipIdentities.Keys.ToList();
        }

        /// <summary>
        /// Sends a RegisterSession command to a target to initiate session
        /// </summary>
        /// <param name="address">IP-Address of the target device</param> 
        /// <param name="port">Port of the target device (default should be 0xAF12)</param> 
        /// <returns>Session Handle</returns>	
        public async Task<uint> RegisterSessionAsync(IPAddress address, ushort port)
        {
            if (sessionHandle != 0)
                return sessionHandle;
            var encapsulation = new Encapsulation {Command = Encapsulation.CommandsEnum.RegisterSession, Length = 4};
            encapsulation.CommandSpecificData.Add(1);       //Protocol version (should be set to 1)
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);       //Session options shall be set to "0"
            encapsulation.CommandSpecificData.Add(0);

            targetIpAddress = address;
            client = new TcpClient(AddressFamily.InterNetwork);
            try
            {
                await client.ConnectAsync(address, port);
            }
            catch (Exception ex)
            {
                switch (ex)
                {
                    case ThreadAbortException _:
                    case StackOverflowException _:
                    case OutOfMemoryException _:
                        throw;
                    default:
                        ((IDisposable)client).Dispose();
                        this.client = null;
                        throw ex;
                }
            }
            stream = client.GetStream();

            byte[] encapData = encapsulation.SerializeToBytes();
            await stream.WriteAsync(encapData, 0, encapData.Length);

            var data = new byte[256];
            var bytes = await stream.ReadAsync(data, 0, data.Length);

            var returnvalue = data[4] + ((uint)data[5] << 8) + ((uint)data[6] << 16) + ((uint)data[7] << 24);
            sessionHandle = returnvalue;
            return returnvalue;
        }

        /// <summary>
        /// Sends a UnRegisterSession command to a target to terminate session
        /// </summary> 
        public async Task UnRegisterSessionAsync()
        {
            var encapsulation = new Encapsulation
            {
                Command = Encapsulation.CommandsEnum.UnRegisterSession,
                Length = 0,
                SessionHandle = sessionHandle,
            };

            byte[] encapData = encapsulation.SerializeToBytes();
            try
            {
                await stream.WriteAsync(encapData, 0, encapData.Length);
            }
            catch (IOException ex)
            {
                //Handle Exception to allow to Close the Stream if the connection was closed by Remote Device
                Console.Error.WriteLine(ex.Message);
            }
            finally
            {
                ((IDisposable)client)?.Dispose();
                client = null;
                stream?.Dispose();
                stream = null;
                sessionHandle = 0;
            }
        }

        public Task ForwardOpenAsync()
        {
            return ForwardOpenAsync(false);
        }

        private UdpClient udpClientReceive;
        private bool udpClientReceiveClosed;

        public async Task ForwardOpenAsync(bool largeForwardOpen)
        {
            if (sessionHandle == 0) //If a Session is not Registered, Try to Registers a Session with the predefined IP-Address and Port
                throw new InvalidOperationException("Register session first.");

            udpClientReceiveClosed = false;
            ushort o_t_headerOffset = 2;                    //Zählt den Sequencecount und evtl 32bit header zu der Länge dazu
            if (O_T_RealTimeFormat == RealTimeFormat.Header32Bit)
                o_t_headerOffset = 6;
            if (O_T_RealTimeFormat == RealTimeFormat.Heartbeat)
                o_t_headerOffset = 0;

            ushort t_o_headerOffset = 2;                    //Zählt den Sequencecount und evtl 32bit header zu der Länge dazu
            if (T_O_RealTimeFormat == RealTimeFormat.Header32Bit)
                t_o_headerOffset = 6;
            if (T_O_RealTimeFormat == RealTimeFormat.Heartbeat)
                t_o_headerOffset = 0;

            var lengthOffset = 5 + (O_T_ConnectionType == ConnectionType.Null ? 0 : 2) + (T_O_ConnectionType == ConnectionType.Null ? 0 : 2);

            var encapsulation = new Encapsulation();
            encapsulation.SessionHandle = sessionHandle;
            encapsulation.Command = Encapsulation.CommandsEnum.SendRRData;
            //!!!!!!-----Length Field at the end!!!!!!!!!!!!!
            
            //---------------Interface Handle CIP
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Interface Handle CIP

            //----------------Timeout
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Timeout

            //Common Packet Format (Table 2-6.1)
            var commonPacketFormat = new Encapsulation.CommonPacketFormat();
            commonPacketFormat.ItemCount = 0x02;

            commonPacketFormat.AddressItem = 0x0000;        //NULL (used for UCMM Messages)
            commonPacketFormat.AddressLength = 0x0000;

            
            commonPacketFormat.DataItem = 0xB2;
            commonPacketFormat.DataLength = (ushort)(41 + (ushort)lengthOffset);
            if (largeForwardOpen)
                commonPacketFormat.DataLength = (ushort)(commonPacketFormat.DataLength + 4);



            //----------------CIP Command "Forward Open" (Service Code 0x54)
            if (!largeForwardOpen)
                commonPacketFormat.Data.Add(0x54);
            //----------------CIP Command "Forward Open"  (Service Code 0x54)

            //----------------CIP Command "large Forward Open" (Service Code 0x5B)
            else
                commonPacketFormat.Data.Add(0x5B);
            //----------------CIP Command "large Forward Open"  (Service Code 0x5B)

            //----------------Requested Path size
            commonPacketFormat.Data.Add(2);
            //----------------Requested Path size

            //----------------Path segment for Class ID
            commonPacketFormat.Data.Add(0x20);
            commonPacketFormat.Data.Add(6);
            //----------------Path segment for Class ID

            //----------------Path segment for Instance ID
            commonPacketFormat.Data.Add(0x24);
            commonPacketFormat.Data.Add(1);
            //----------------Path segment for Instace ID

            //----------------Priority and Time/Tick - Table 3-5.16 (Vol. 1)
            commonPacketFormat.Data.Add(0x03);
            //----------------Priority and Time/Tick

            //----------------Timeout Ticks - Table 3-5.16 (Vol. 1)
            commonPacketFormat.Data.Add(0xfa);
            //----------------Timeout Ticks

            connectionID_O_T = Convert.ToUInt32(new Random().Next(0xfffffff));
            connectionID_T_O = Convert.ToUInt32(new Random().Next(0xfffffff)+1);
            commonPacketFormat.Data.Add((byte)connectionID_O_T);
            commonPacketFormat.Data.Add((byte)(connectionID_O_T >> 8));
            commonPacketFormat.Data.Add((byte)(connectionID_O_T >> 16));
            commonPacketFormat.Data.Add((byte)(connectionID_O_T >> 24));


            commonPacketFormat.Data.Add((byte)connectionID_T_O);
            commonPacketFormat.Data.Add((byte)(connectionID_T_O >> 8));
            commonPacketFormat.Data.Add((byte)(connectionID_T_O >> 16));
            commonPacketFormat.Data.Add((byte)(connectionID_T_O >> 24));

            connectionSerialNumber = Convert.ToUInt16(new Random().Next(0xFFFF)+2);
            commonPacketFormat.Data.Add((byte)connectionSerialNumber);
            commonPacketFormat.Data.Add((byte)(connectionSerialNumber >> 8));

            //----------------Originator Vendor ID
            commonPacketFormat.Data.Add(0xFF);
            commonPacketFormat.Data.Add(0);
            //----------------Originaator Vendor ID

            //----------------Originator Serial Number
            commonPacketFormat.Data.Add(0xFF);
            commonPacketFormat.Data.Add(0xFF);
            commonPacketFormat.Data.Add(0xFF);
            commonPacketFormat.Data.Add(0xFF);
            //----------------Originator Serial Number

            //----------------Timeout Multiplier
            commonPacketFormat.Data.Add(3);
            //----------------Timeout Multiplier

            //----------------Reserved
            commonPacketFormat.Data.Add(0);
            commonPacketFormat.Data.Add(0);
            commonPacketFormat.Data.Add(0);
            //----------------Reserved

            //----------------Requested Packet Rate O->T in Microseconds
            commonPacketFormat.Data.Add((byte)RequestedPacketRate_O_T);
            commonPacketFormat.Data.Add((byte)(RequestedPacketRate_O_T >> 8));
            commonPacketFormat.Data.Add((byte)(RequestedPacketRate_O_T >> 16));
            commonPacketFormat.Data.Add((byte)(RequestedPacketRate_O_T >> 24));
            //----------------Requested Packet Rate O->T in Microseconds

            //----------------O->T Network Connection Parameters
            var redundantOwner = O_T_OwnerRedundant;
            var connectionType = (byte)O_T_ConnectionType; //1=Multicast, 2=P2P
            var priority = (byte)O_T_Priority;         //00=low; 01=High; 10=Scheduled; 11=Urgent
            var variableLength = O_T_VariableLength;       //0=fixed; 1=variable
            var connectionSize = (ushort)(O_T_Length + o_t_headerOffset);      //The maximum size in bytes og the data for each direction (were applicable) of the connection. For a variable -> maximum
            uint NetworkConnectionParameters = (ushort)((ushort)(connectionSize & 0x1FF) | (Convert.ToUInt16(variableLength) << 9) | ((priority & 0x03) << 10) | ((connectionType & 0x03) << 13) | (Convert.ToUInt16(redundantOwner) << 15));
            if (largeForwardOpen)
                NetworkConnectionParameters = (uint)(connectionSize & 0xFFFF) | (Convert.ToUInt32(variableLength) << 25) | (uint)((priority & 0x03) << 26) | (uint)((connectionType & 0x03) << 29) | (Convert.ToUInt32(redundantOwner) << 31);
            commonPacketFormat.Data.Add((byte)NetworkConnectionParameters);
            commonPacketFormat.Data.Add((byte)(NetworkConnectionParameters >> 8));
            if (largeForwardOpen)
            {
                commonPacketFormat.Data.Add((byte)(NetworkConnectionParameters >> 16));
                commonPacketFormat.Data.Add((byte)(NetworkConnectionParameters >> 24));
            }
            //----------------O->T Network Connection Parameters

            //----------------Requested Packet Rate T->O in Microseconds
            commonPacketFormat.Data.Add((byte)RequestedPacketRate_T_O);
            commonPacketFormat.Data.Add((byte)(RequestedPacketRate_T_O >> 8));
            commonPacketFormat.Data.Add((byte)(RequestedPacketRate_T_O >> 16));
            commonPacketFormat.Data.Add((byte)(RequestedPacketRate_T_O >> 24));
            //----------------Requested Packet Rate T->O in Microseconds

            //----------------T->O Network Connection Parameters


            redundantOwner = T_O_OwnerRedundant;
            connectionType = (byte)T_O_ConnectionType; //1=Multicast, 2=P2P
            priority = (byte)T_O_Priority;
            variableLength = T_O_VariableLength;
            connectionSize = (ushort)(T_O_Length  + t_o_headerOffset);
            NetworkConnectionParameters = (ushort)((ushort)(connectionSize & 0x1FF) | (Convert.ToUInt16(variableLength) << 9) | ((priority & 0x03) << 10) | ((connectionType & 0x03) << 13) | (Convert.ToUInt16(redundantOwner) << 15));
            if (largeForwardOpen)
                NetworkConnectionParameters = (uint)(connectionSize & 0xFFFF) | (Convert.ToUInt32(variableLength) << 25) | (uint)((priority & 0x03) << 26) | (uint)((connectionType & 0x03) << 29) | (Convert.ToUInt32(redundantOwner) << 31);
            commonPacketFormat.Data.Add((byte)NetworkConnectionParameters);
            commonPacketFormat.Data.Add((byte)(NetworkConnectionParameters >> 8));
            if (largeForwardOpen)
            {
                commonPacketFormat.Data.Add((byte)(NetworkConnectionParameters >> 16));
                commonPacketFormat.Data.Add((byte)(NetworkConnectionParameters >> 24));
            }
            //----------------T->O Network Connection Parameters

            //----------------Transport Type/Trigger
            commonPacketFormat.Data.Add(0x01);
            //X------- = 0= Client; 1= Server
            //-XXX---- = Production Trigger, 0 = Cyclic, 1 = CoS, 2 = Application Object
            //----XXXX = Transport class, 0 = Class 0, 1 = Class 1, 2 = Class 2, 3 = Class 3
            //----------------Transport Type Trigger
            //Connection Path size 
            commonPacketFormat.Data.Add((byte)(0x2 + (O_T_ConnectionType == ConnectionType.Null ? 0 : 1) + (T_O_ConnectionType == ConnectionType.Null ? 0 : 1) ));
            //Verbindugspfad
            commonPacketFormat.Data.Add(0x20);
            commonPacketFormat.Data.Add(AssemblyObjectClass);
            commonPacketFormat.Data.Add(0x24);
            commonPacketFormat.Data.Add(ConfigurationAssemblyInstanceID);
            if (O_T_ConnectionType != ConnectionType.Null)
            {
                commonPacketFormat.Data.Add(0x2C);
                commonPacketFormat.Data.Add(O_T_InstanceID);
            }
            if (T_O_ConnectionType != ConnectionType.Null)
            {
                commonPacketFormat.Data.Add(0x2C);
                commonPacketFormat.Data.Add(T_O_InstanceID);
            }
            
            //AddSocket Addrress Item O->T

            uint sinAddress;
            if (O_T_ConnectionType == ConnectionType.Multicast)
            {
                sinAddress = GetMulticastAddress(this.targetIpAddress);
                multicastAddress = sinAddress;
            }
            else
            {
                sinAddress = 0;
            }

            var socketaddrInfo_O_T = new Encapsulation.SocketAddress(2, OriginatorUDPPort, sinAddress);

            commonPacketFormat.SocketaddrInfo_O_T = socketaddrInfo_O_T;

            var commonPacketBytes = commonPacketFormat.SerializeToBytes();
            encapsulation.Length = (ushort)(commonPacketBytes.Length+6);//(ushort)(57 + (ushort)lengthOffset);
            //20 04 24 01 2C 65 2C 6B

            var encapsulationBytes = encapsulation.SerializeToBytes();
            var dataToWrite = new byte[encapsulationBytes.Length + commonPacketBytes.Length];
            Buffer.BlockCopy(encapsulationBytes, 0, dataToWrite, 0, encapsulationBytes.Length);
            Buffer.BlockCopy(commonPacketBytes, 0, dataToWrite, encapsulationBytes.Length, commonPacketBytes.Length);
            
            await stream.WriteAsync(dataToWrite, 0, dataToWrite.Length);
            var data = new byte[564];

            var bytes = await stream.ReadAsync(data, 0, data.Length);

            //--------------------------BEGIN Error?
            if (data[42] != 0)      //Exception codes see "Table B-1.1 CIP General Status Codes"
            {
                if (data[42] == 0x1)
                    if (data[43] == 0)
                        throw new CIPException("Connection failure, General Status Code: " + data[42]);
                    else
                        throw new CIPException("Connection failure, General Status Code: " + data[42] + " Additional Status Code: " + ((data[45] << 8) | data[44]) + " " + ConnectionManagerObject.GetExtendedStatus((uint)((data[45] << 8) | data[44])));
                throw new CIPException(GeneralStatusCodes.GetStatusCode(data[42]));
            }
            //--------------------------END Error?
            //Read the Network ID from the Reply (see 3-3.7.1.1)
            var itemCount = data[30] + (data[31] << 8);
            var lengthUnconectedDataItem = data[38] + (data[39] << 8);
            connectionID_O_T = data[44] + (uint)(data[45] << 8) + (uint)(data[46] << 16) + (uint)(data[47] << 24);
            connectionID_T_O = data[48] + (uint)(data[49] << 8) + (uint)(data[50] << 16) + (uint)(data[51] << 24);

            //Is a SocketInfoItem present?
            var numberOfCurrentItem = 0;
            while (itemCount > 2)
            {
                var itemStartIndex = 40 + lengthUnconectedDataItem + 20 * numberOfCurrentItem;
                var typeID = data[itemStartIndex] + (data[itemStartIndex + 1] << 8);
                if (typeID == 0x8001)
                {
                    var socketInfoItem = Encapsulation.SocketAddress.FromBytes(data, itemStartIndex + 4);
                    if (T_O_ConnectionType == ConnectionType.Multicast)
                        multicastAddress = socketInfoItem.SIN_Address;
                    TargetUDPPort = socketInfoItem.SIN_port;
                }
                numberOfCurrentItem++;
                itemCount--;
            }

            //Open UDP-Port
            var endPointReceive = new IPEndPoint(System.Net.IPAddress.Any, OriginatorUDPPort);
            udpClientReceive = new UdpClient(endPointReceive);
            var s = new UdpState {e = endPointReceive, u = udpClientReceive};
            if (multicastAddress != 0)
            {
                var multicast = new IPAddress(multicastAddress);
                udpClientReceive.JoinMulticastGroup(multicast);
            }

            var sendThread = new Thread(SendUdpThread);
            sendThread.Start();

            var asyncResult = udpClientReceive.BeginReceive(ReceiveCallbackClass1, s);
        }

        public Task LargeForwardOpenAsync()
        {
            return ForwardOpenAsync(true);
        }

        private ushort o_t_detectedLength;
        /// <summary>
        /// Detects the Length of the data Originator -> Target.
        /// The Method uses an Explicit Message to detect the length.
        /// The IP-Address, Port and the Instance ID has to be defined before
        /// </summary>
        public async Task<ushort> Detect_O_T_Length ()
        {
            if (o_t_detectedLength == 0)
            {
                if (sessionHandle == 0)
                    throw new InvalidOperationException("Register session first.");
                var data = await GetAttributeSingleAsync(0x04, O_T_InstanceID, 3);
                o_t_detectedLength = (ushort)data.Length;
                return o_t_detectedLength;
            }
            return o_t_detectedLength;
        }

        private ushort t_o_detectedLength;

        /// <summary>
        /// Detects the Length of the data Target -> Originator.
        /// The Method uses an Explicit Message to detect the length.
        /// The IP-Address, Port and the Instance ID has to be defined before
        /// </summary>
        public async Task<ushort> Detect_T_O_LengthAsync()
        {
            if (t_o_detectedLength == 0)
            {
                if (sessionHandle == 0)
                    throw new InvalidOperationException("Register session first.");
                var data = await GetAttributeSingleAsync(0x04, T_O_InstanceID, 3);
                t_o_detectedLength = (ushort)data.Length;
                return t_o_detectedLength;
            }
            return t_o_detectedLength;
        }

        /// <returns>Value of IP the multicast address. The value is in big-endian format</returns>
        private static uint GetMulticastAddress(IPAddress ipAddress)
        {
            // native order
            var addressBytes = ipAddress.GetAddressBytes();
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(addressBytes);
            }
            uint deviceIPAddress = BitConverter.ToUInt32(addressBytes, 0);

            var cip_Mcast_Base_Addr = 0xEFC00100;
            uint cip_Host_Mask = 0x3FF;
            uint netmask = 0;

            //Class A Network?
            if (deviceIPAddress <= 0x7FFFFFFF)
                netmask = 0xFF000000;
            //Class B Network?
            if (deviceIPAddress >= 0x80000000 && deviceIPAddress <= 0xBFFFFFFF)
                netmask = 0xFFFF0000;
            //Class C Network?
            if (deviceIPAddress >= 0xC0000000 && deviceIPAddress <= 0xDFFFFFFF)
                netmask = 0xFFFFFF00;

            var hostID = deviceIPAddress & ~netmask;
            var mcastIndex = hostID - 1;
            mcastIndex = mcastIndex & cip_Host_Mask;

            var mcastAddr = cip_Mcast_Base_Addr + mcastIndex * 32;
            return BitConverter.IsLittleEndian ? SwapEndianness(mcastAddr) : mcastAddr;
        }
        
        private static uint SwapEndianness(uint value)
        {
            var b1 = value & 0xff;
            var b2 = (value >> 8) & 0xff;
            var b3 = (value >> 16) & 0xff;
            var b4 = (value >> 24) & 0xff;

            return b1 << 24 | b2 << 16 | b3 << 8 | b4;
        } 

        public async Task ForwardCloseAsync()
        {
            //First stop the Thread which send data

            this.stopUdpThread = true;

            var lengthOffset = 5 + (O_T_ConnectionType == ConnectionType.Null ? 0 : 2) + (T_O_ConnectionType == ConnectionType.Null ? 0 : 2);

            var encapsulation = new Encapsulation();
            encapsulation.SessionHandle = sessionHandle;
            encapsulation.Command = Encapsulation.CommandsEnum.SendRRData;
            encapsulation.Length = (ushort)(16 +17+ (ushort)lengthOffset);
            //---------------Interface Handle CIP
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Interface Handle CIP

            //----------------Timeout
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Timeout

            //Common Packet Format (Table 2-6.1)
            var commonPacketFormat = new Encapsulation.CommonPacketFormat();
            commonPacketFormat.ItemCount = 0x02;

            commonPacketFormat.AddressItem = 0x0000;        //NULL (used for UCMM Messages)
            commonPacketFormat.AddressLength = 0x0000;


            commonPacketFormat.DataItem = 0xB2;
            commonPacketFormat.DataLength = (ushort)(17 + (ushort)lengthOffset);



            //----------------CIP Command "Forward Close"
            commonPacketFormat.Data.Add(0x4E);
            //----------------CIP Command "Forward Close"

            //----------------Requested Path size
            commonPacketFormat.Data.Add(2);
            //----------------Requested Path size

            //----------------Path segment for Class ID
            commonPacketFormat.Data.Add(0x20);
            commonPacketFormat.Data.Add(6);
            //----------------Path segment for Class ID

            //----------------Path segment for Instance ID
            commonPacketFormat.Data.Add(0x24);
            commonPacketFormat.Data.Add(1);
            //----------------Path segment for Instace ID

            //----------------Priority and Time/Tick - Table 3-5.16 (Vol. 1)
            commonPacketFormat.Data.Add(0x03);
            //----------------Priority and Time/Tick

            //----------------Timeout Ticks - Table 3-5.16 (Vol. 1)
            commonPacketFormat.Data.Add(0xfa);
            //----------------Timeout Ticks

            //Connection serial number
            commonPacketFormat.Data.Add((byte)connectionSerialNumber);
            commonPacketFormat.Data.Add((byte)(connectionSerialNumber >> 8));
            //connection seruial number

            //----------------Originator Vendor ID
            commonPacketFormat.Data.Add(0xFF);
            commonPacketFormat.Data.Add(0);
            //----------------Originaator Vendor ID

            //----------------Originator Serial Number
            commonPacketFormat.Data.Add(0xFF);
            commonPacketFormat.Data.Add(0xFF);
            commonPacketFormat.Data.Add(0xFF);
            commonPacketFormat.Data.Add(0xFF);
            //----------------Originator Serial Number

            //Connection Path size 
            commonPacketFormat.Data.Add((byte)(0x2 + (O_T_ConnectionType == ConnectionType.Null ? 0 : 1) + (T_O_ConnectionType == ConnectionType.Null ? 0 : 1)));
            //Reserved
            commonPacketFormat.Data.Add(0);
            //Reserved


            //Verbindugspfad
            commonPacketFormat.Data.Add(0x20);
            commonPacketFormat.Data.Add(AssemblyObjectClass);
            commonPacketFormat.Data.Add(0x24);
            commonPacketFormat.Data.Add(ConfigurationAssemblyInstanceID);
            if (O_T_ConnectionType != ConnectionType.Null)
            {
                commonPacketFormat.Data.Add(0x2C);
                commonPacketFormat.Data.Add(O_T_InstanceID);
            }
            if (T_O_ConnectionType != ConnectionType.Null)
            {
                commonPacketFormat.Data.Add(0x2C);
                commonPacketFormat.Data.Add(T_O_InstanceID);
            }

            byte[] encapData = encapsulation.SerializeToBytes();
            byte[] packetData = commonPacketFormat.SerializeToBytes();
            var dataToWrite = new byte[encapData.Length + packetData.Length];
            Buffer.BlockCopy(encapData, 0, dataToWrite, 0, encapData.Length);
            Buffer.BlockCopy(packetData, 0, dataToWrite, encapData.Length, packetData.Length);

            try
            {
                await stream.WriteAsync(dataToWrite, 0, dataToWrite.Length);

                var data = new byte[564];
                var bytes = await stream.ReadAsync(data, 0, data.Length);

                //--------------------------BEGIN Error?
                if (data[42] != 0)      //Exception codes see "Table B-1.1 CIP General Status Codes"
                    throw new CIPException(GeneralStatusCodes.GetStatusCode(data[42]));
            }
            catch (Exception e)
            {
                // TODO: Change to IOException?
                //Handle Exception  to allow Forward close if the connection was closed by the Remote Device before
            }
            finally
            {
                //Close the Socket for Receive
                udpClientReceiveClosed = true;
                udpClientReceive.Close();
            }
        }

        private bool stopUdpThread;
        private int sequence;
        private void SendUdpThread()
        {
            var udpClientsend = new UdpClient();
            this.stopUdpThread = false;
            uint sequenceCount = 0;


            while (!this.stopUdpThread)
            {
                var o_t_IOData = new byte[564];
                var endPointsend = new IPEndPoint(targetIpAddress, TargetUDPPort);
               
                //---------------Item count
                o_t_IOData[0] = 2;
                o_t_IOData[1] = 0;
                //---------------Item count

                //---------------Type ID
                o_t_IOData[2] = 0x02;
                o_t_IOData[3] = 0x80;
                //---------------Type ID

                //---------------Length
                o_t_IOData[4] = 0x08;
                o_t_IOData[5] = 0x00;
                //---------------Length

                //---------------connection ID
                sequenceCount++;
                o_t_IOData[6] = (byte)connectionID_O_T;
                o_t_IOData[7] = (byte)(connectionID_O_T >> 8); 
                o_t_IOData[8] = (byte)(connectionID_O_T >> 16); 
                o_t_IOData[9] = (byte)(connectionID_O_T >> 24);
                //---------------connection ID     

                //---------------sequence count
                o_t_IOData[10] = (byte)sequenceCount;
                o_t_IOData[11] = (byte)(sequenceCount >> 8);
                o_t_IOData[12] = (byte)(sequenceCount >> 16);
                o_t_IOData[13] = (byte)(sequenceCount >> 24);
                //---------------sequence count            

                //---------------Type ID
                o_t_IOData[14] = 0xB1;
                o_t_IOData[15] = 0x00;
                //---------------Type ID

                ushort headerOffset = 0;
                if (O_T_RealTimeFormat == RealTimeFormat.Header32Bit)
                    headerOffset = 4;
                if (O_T_RealTimeFormat == RealTimeFormat.Heartbeat)
                    headerOffset = 0;
                var o_t_Length = (ushort)(O_T_Length + headerOffset+2);   //Modeless and zero Length

                //---------------Length
                o_t_IOData[16] = (byte)o_t_Length;
                o_t_IOData[17] = (byte)(o_t_Length >> 8);
                //---------------Length

                //---------------Sequence count
                sequence++;
                if (O_T_RealTimeFormat != RealTimeFormat.Heartbeat)
                {
                    o_t_IOData[18] = (byte)sequence;
                    o_t_IOData[19] = (byte)(sequence >> 8);
                }
                //---------------Sequence count

                if (O_T_RealTimeFormat == RealTimeFormat.Header32Bit)
                {
                    o_t_IOData[20] = 1;
                    o_t_IOData[21] = 0;
                    o_t_IOData[22] = 0;
                    o_t_IOData[23] = 0;

                }

                //---------------Write data
                lock (_O_T_IOData_lock)
                {
                    Array.Copy(_O_T_IOData, 0, o_t_IOData, 20 + headerOffset, O_T_Length);
                }
                //---------------Write data
                udpClientsend.Send(o_t_IOData, O_T_Length+20+headerOffset, endPointsend);
                Thread.Sleep((int)RequestedPacketRate_O_T/1000);
            }

            udpClientsend.Close();
        }

        private void ReceiveCallbackClass1(IAsyncResult ar)
        {          
            var u = ((UdpState)ar.AsyncState).u;
            if (udpClientReceiveClosed)
                return;

            byte[] receiveBytes;
            try
            {
                u.BeginReceive(ReceiveCallbackClass1, (UdpState)ar.AsyncState);

                var e = ((UdpState)ar.AsyncState).e;
                receiveBytes = u.EndReceive(ar, ref e);
            }
            catch (Exception ex)
            {
                if (ex is ObjectDisposedException || ex is SocketException)
                {
                    // TODO: Log it as a trace here
                    return;
                }
                // Wasn't an exception we were looking for so rethrow it.
                throw;
            }

            // EndReceive worked and we have received data and remote endpoint

            if (receiveBytes.Length > 20)
            {
                //Get the connection ID
                var connectionID = (uint)(receiveBytes[6] | (receiveBytes[7] << 8) | (receiveBytes[8] << 16) | (receiveBytes[9] << 24));


                if (connectionID == connectionID_T_O)
                {
                    ushort headerOffset = 0;
                    if (T_O_RealTimeFormat == RealTimeFormat.Header32Bit)
                        headerOffset = 4;
                    if (T_O_RealTimeFormat == RealTimeFormat.Heartbeat)
                        headerOffset = 0;

                    lock (_T_O_IOData_lock)
                    {
                        Array.Copy(receiveBytes, 20 + headerOffset, _T_O_IOData, 0,
                            receiveBytes.Length - 20 - headerOffset);
                    }

                    //Console.WriteLine(T_O_IOData[0]);
                    OnImplicitMessageReceived(new ImplicitMessageReceivedArgs(connectionID));
                }
            }
            LastReceivedImplicitMessage = DateTime.Now;
        }

        /// <summary>
        /// Sends a RegisterSession command to a target to initiate session with the Standard or predefined Port (Standard: 0xAF12).
        /// For the scheme, use "ethernet-ip-1" or "ethernet-ip-2" all others default to "ethernet-ip-2" port, unless explicitly defined.
        /// </summary>
        /// <param name="address">IP-Address of the target device</param> 
        /// <returns>Session Handle</returns>	
        public Task<uint> RegisterSessionAsync(Uri address)
        {
            if (!address.IsAbsoluteUri)
            {
                throw new ArgumentException("address must be absolute", nameof(address));
            }

            ushort port;
            if (!address.IsDefaultPort)
            {
                port = (ushort)address.Port;
            }
            else
            {
                if (address.Scheme.Equals("ethernet-ip-1", StringComparison.OrdinalIgnoreCase))
                {
                    port = 0x08AE;
                }
                else
                {
                    // ethernet-ip-2 or default
                    port = 0xAF12;
                }
            }

            var ipAddress = Dns.GetHostAddresses(address.Host)
                .First(x => x.AddressFamily == AddressFamily.InterNetwork);

            return RegisterSessionAsync(ipAddress, port);
        }

        public async Task<byte[]> GetAttributeSingleAsync(int classID, int instanceID, int attributeID)
        {
            var requestedPath = GetEPath(classID, instanceID, attributeID);
            if (sessionHandle == 0)             //If a Session is not Registers, Try to Registers a Session with the predefined IP-Address and Port
                throw new InvalidOperationException("Register session first.");
            var dataToSend = new byte[42+ requestedPath.Length];
            var encapsulation = new Encapsulation();
            encapsulation.SessionHandle = sessionHandle;
            encapsulation.Command = Encapsulation.CommandsEnum.SendRRData;
            encapsulation.Length = (ushort)(18 + requestedPath.Length);
            //---------------Interface Handle CIP
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Interface Handle CIP

            //----------------Timeout
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Timeout

            //Common Packet Format (Table 2-6.1)
            var commonPacketFormat = new Encapsulation.CommonPacketFormat();
            commonPacketFormat.ItemCount = 0x02;

            commonPacketFormat.AddressItem = 0x0000;        //NULL (used for UCMM Messages)
            commonPacketFormat.AddressLength = 0x0000;

            commonPacketFormat.DataItem = 0xB2;
            commonPacketFormat.DataLength = (ushort)(2 + requestedPath.Length);



            //----------------CIP Command "Get Attribute Single"
            commonPacketFormat.Data.Add((byte)CIPCommonServices.Get_Attribute_Single);
            //----------------CIP Command "Get Attribute Single"

            //----------------Requested Path size (number of 16 bit words)
            commonPacketFormat.Data.Add((byte)(requestedPath.Length / 2));
            //----------------Requested Path size (number of 16 bit words)

            //----------------Path segment for Class ID
            //----------------Path segment for Class ID

            //----------------Path segment for Instance ID
            //----------------Path segment for Instace ID

            //----------------Path segment for Attribute ID
            //----------------Path segment for Attribute ID

            for (var i = 0; i < requestedPath.Length; i++)
                commonPacketFormat.Data.Add(requestedPath[i]);

            byte[] encapData = encapsulation.SerializeToBytes();
            byte[] packetData = commonPacketFormat.SerializeToBytes();
            var dataToWrite = new byte[encapData.Length + packetData.Length];
            Buffer.BlockCopy(encapData, 0, dataToWrite, 0, encapData.Length);
            Buffer.BlockCopy(packetData, 0, dataToWrite, encapData.Length, packetData.Length);

            await stream.WriteAsync(dataToWrite, 0, dataToWrite.Length);

            var data = new byte[564];
            var bytes = await stream.ReadAsync(data, 0, data.Length);

            //--------------------------BEGIN Error?
            if (data[42] != 0)      //Exception codes see "Table B-1.1 CIP General Status Codes"
                throw new CIPException(GeneralStatusCodes.GetStatusCode(data[42]));
            //--------------------------END Error?

            var returnData = new byte[bytes - 44];
            Buffer.BlockCopy(data, 44, returnData, 0, bytes-44);

            return returnData;
        }

        /// <summary>
        /// Implementation of Common Service "Get_Attribute_All" - Service Code: 0x01
        /// </summary>
        /// <param name="classID">Class id of requested Attributes</param> 
        /// <param name="instanceID">Instance of Requested Attributes (0 for class Attributes)</param> 
        /// <returns>Session Handle</returns>	
        public async Task<byte[]> GetAttributeAllAsync(int classID, int instanceID)
        {
            var requestedPath = GetEPath(classID, instanceID, 0);
            if (sessionHandle == 0)             //If a Session is not Registered, Try to Registers a Session with the predefined IP-Address and Port
                throw new InvalidOperationException("Register session first.");
            var dataToSend = new byte[42 + requestedPath.Length];
            var encapsulation = new Encapsulation();
            encapsulation.SessionHandle = sessionHandle;
            encapsulation.Command = Encapsulation.CommandsEnum.SendRRData;
            encapsulation.Length = (ushort)(18 + requestedPath.Length);
            //---------------Interface Handle CIP
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Interface Handle CIP

            //----------------Timeout
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Timeout

            //Common Packet Format (Table 2-6.1)
            var commonPacketFormat = new Encapsulation.CommonPacketFormat();
            commonPacketFormat.ItemCount = 0x02;

            commonPacketFormat.AddressItem = 0x0000;        //NULL (used for UCMM Messages)
            commonPacketFormat.AddressLength = 0x0000;

            commonPacketFormat.DataItem = 0xB2;
            commonPacketFormat.DataLength = (ushort)(2 + requestedPath.Length); //WAS 6



            //----------------CIP Command "Get Attribute All"
            commonPacketFormat.Data.Add((byte)CIPCommonServices.Get_Attributes_All);
            //----------------CIP Command "Get Attribute All"

            //----------------Requested Path size
            commonPacketFormat.Data.Add((byte)(requestedPath.Length / 2));
            //----------------Requested Path size

            //----------------Path segment for Class ID
            //----------------Path segment for Class ID

            //----------------Path segment for Instance ID
            //----------------Path segment for Instace ID
            for (var i = 0; i < requestedPath.Length; i++)
                commonPacketFormat.Data.Add(requestedPath[i]);

            byte[] encapData = encapsulation.SerializeToBytes();
            byte[] packetData = commonPacketFormat.SerializeToBytes();
            var dataToWrite = new byte[encapData.Length + packetData.Length];
            Buffer.BlockCopy(encapData, 0, dataToWrite, 0, encapData.Length);
            Buffer.BlockCopy(packetData, 0, dataToWrite, encapData.Length, packetData.Length);
           

            await stream.WriteAsync(dataToWrite, 0, dataToWrite.Length);

            var data = new byte[564];
            var bytes = await stream.ReadAsync(data, 0, data.Length);
            //--------------------------BEGIN Error?
            if (data[42] != 0)      //Exception codes see "Table B-1.1 CIP General Status Codes"
                throw new CIPException(GeneralStatusCodes.GetStatusCode(data[42]));
            //--------------------------END Error?

            var returnData = new byte[bytes - 44];
            Buffer.BlockCopy(data, 44, returnData, 0, bytes - 44);

            return returnData;
        }

        public async Task<byte[]> SetAttributeSingleAsync(int classID, int instanceID, int attributeID, byte[] value)
        {
            var requestedPath = GetEPath(classID, instanceID, attributeID);
            if (sessionHandle == 0)             //If a Session is not Registers, Try to Registers a Session with the predefined IP-Address and Port
                throw new InvalidOperationException("Register session first.");
            var dataToSend = new byte[42 + value.Length + requestedPath.Length];
            var encapsulation = new Encapsulation();
            encapsulation.SessionHandle = sessionHandle;
            encapsulation.Command = Encapsulation.CommandsEnum.SendRRData;
            encapsulation.Length = (ushort)(18+value.Length + requestedPath.Length);
            //---------------Interface Handle CIP
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Interface Handle CIP

            //----------------Timeout
            encapsulation.CommandSpecificData.Add(0);
            encapsulation.CommandSpecificData.Add(0);
            //----------------Timeout

            //Common Packet Format (Table 2-6.1)
            var commonPacketFormat = new Encapsulation.CommonPacketFormat();
            commonPacketFormat.ItemCount = 0x02;

            commonPacketFormat.AddressItem = 0x0000;        //NULL (used for UCMM Messages)
            commonPacketFormat.AddressLength = 0x0000;

            commonPacketFormat.DataItem = 0xB2;
            commonPacketFormat.DataLength = (ushort)(2 + value.Length+requestedPath.Length);



            //----------------CIP Command "Set Attribute Single"
            commonPacketFormat.Data.Add((byte)CIPCommonServices.Set_Attribute_Single);
            //----------------CIP Command "Set Attribute Single"

            //----------------Requested Path size (number of 16 bit words)
            commonPacketFormat.Data.Add((byte)(requestedPath.Length/2));
            //----------------Requested Path size (number of 16 bit words)

            //----------------Path segment for Class ID
            //----------------Path segment for Class ID

            //----------------Path segment for Instance ID
            //----------------Path segment for Instace ID

            //----------------Path segment for Attribute ID
            //----------------Path segment for Attribute ID
            for (var i = 0; i < requestedPath.Length; i++)
                commonPacketFormat.Data.Add(requestedPath[i]);

            //----------------Data
            for (var i = 0; i < value.Length; i++)
                commonPacketFormat.Data.Add(value[i]);
            //----------------Data

            byte[] encapData = encapsulation.SerializeToBytes();
            byte[] packetData = commonPacketFormat.SerializeToBytes();
            var dataToWrite = new byte[encapData.Length + packetData.Length];
            Buffer.BlockCopy(encapData, 0, dataToWrite, 0, encapData.Length);
            Buffer.BlockCopy(packetData, 0, dataToWrite, encapData.Length, packetData.Length);

            await stream.WriteAsync(dataToWrite, 0, dataToWrite.Length);

            var data = new byte[564];
            var bytes = await stream.ReadAsync(data, 0, data.Length);

            //--------------------------BEGIN Error?
            if (data[42] != 0)      //Exception codes see "Table B-1.1 CIP General Status Codes"
                throw new CIPException(GeneralStatusCodes.GetStatusCode(data[42]));
            //--------------------------END Error?

            var returnData = new byte[bytes - 44];
            Buffer.BlockCopy(data, 44, returnData, 0, bytes - 44);

            return returnData;
        }

        /// <summary>
        /// Get the Encrypted Request Path - See Volume 1 Appendix C (C9)
        /// e.g. for 8 Bit: 20 05 24 02 30 01
        /// for 16 Bit: 21 00 05 00 24 02 30 01
        /// </summary>
        /// <param name="classID">Requested Class ID</param>
        /// <param name="instanceID">Requested Instance ID</param>
        /// <param name="attributeID">Requested Attribute ID - if "0" the attribute will be ignored</param>
        /// <returns>Encrypted Request Path</returns>
        private static byte[] GetEPath(int classID, int instanceID, int attributeID)
        {
            var byteCount = 0;
            if (classID < 0xff)
                byteCount = byteCount + 2;
            else
                byteCount = byteCount + 4;
           
            if (instanceID < 0xff)
                byteCount = byteCount + 2;
            else
                byteCount = byteCount + 4;
            if (attributeID != 0)
                if (attributeID < 0xff)
                    byteCount = byteCount + 2;
                else
                    byteCount = byteCount + 4;

            var returnValue = new byte[byteCount];
            byteCount = 0;
            if (classID < 0xff)
            {
                returnValue[byteCount] = 0x20;
                returnValue[byteCount+1] = (byte)classID;
                byteCount = byteCount + 2;
            }
            else
            {
                returnValue[byteCount] = 0x21;
                returnValue[byteCount + 1] = 0;                             //Padded Byte
                returnValue[byteCount + 2] = (byte)classID;                 //LSB
                returnValue[byteCount + 3] = (byte)(classID>>8);            //MSB
                byteCount = byteCount + 4;
            }


            if (instanceID < 0xff)
            {
                returnValue[byteCount] = 0x24;
                returnValue[byteCount + 1] = (byte)instanceID;
                byteCount = byteCount + 2;
            }
            else
            {
                returnValue[byteCount] = 0x25;
                returnValue[byteCount + 1] = 0;                                //Padded Byte
                returnValue[byteCount + 2] = (byte)instanceID;                 //LSB
                returnValue[byteCount + 3] = (byte)(instanceID >> 8);          //MSB
                byteCount = byteCount + 4;
            }
            if (attributeID != 0)
                if (attributeID < 0xff)
                {
                    returnValue[byteCount] = 0x30;
                    returnValue[byteCount + 1] = (byte)attributeID;
                    byteCount = byteCount + 2;
                }
                else
                {
                    returnValue[byteCount] = 0x31;
                    returnValue[byteCount + 1] = 0;                                 //Padded Byte
                    returnValue[byteCount + 2] = (byte)attributeID;                 //LSB
                    returnValue[byteCount + 3] = (byte)(attributeID >> 8);          //MSB
                    byteCount = byteCount + 4;
                }

            return returnValue;
        }

        /// <summary>
        /// Implementation of Common Service "Get_Attribute_All" - Service Code: 0x01
        /// </summary>
        /// <param name="classID">Class id of requested Attributes</param> 
        public Task<byte[]> GetAttributeAllAsync(int classID)
        {
            return GetAttributeAllAsync(classID, 0);
        }

        private IdentityObject identityObject;
        /// <summary>
        /// Implementation of the identity Object (Class Code: 0x01) - Required Object according to CIP-Specification
        /// </summary>
        public IdentityObject IdentityObject
        {
            get
            {
                if (identityObject == null)
                    identityObject = new IdentityObject(this);
                return identityObject;

            }
        }

        private MessageRouterObject messageRouterObject;
        /// <summary>
        /// Implementation of the Message Router Object (Class Code: 0x02) - Required Object according to CIP-Specification
        /// </summary>
        public MessageRouterObject MessageRouterObject
        {
            get
            {
                if (messageRouterObject == null)
                    messageRouterObject = new MessageRouterObject(this);
                return messageRouterObject;

            }
        }

        private AssemblyObject assemblyObject;
        /// <summary>
        /// Implementation of the Assembly Object (Class Code: 0x04)
        /// </summary>
        public AssemblyObject AssemblyObject
        {
            get
            {
                if (assemblyObject == null)
                    assemblyObject = new AssemblyObject(this);
                return assemblyObject;
            }
        }

        private TcpIpInterfaceObject tcpIpInterfaceObject;
        /// <summary>
        /// Implementation of the TCP/IP Object (Class Code: 0xF5) - Required Object according to CIP-Specification
        /// </summary>
        public TcpIpInterfaceObject TcpIpInterfaceObject
        {
            get
            {
                if (tcpIpInterfaceObject == null)
                    tcpIpInterfaceObject = new TcpIpInterfaceObject(this);
                return tcpIpInterfaceObject;

            }
        }

        /// <summary>
        /// Provides Access to the Class 1 Real-Time IO-Data Originator -> Target for Implicit Messaging    
        /// </summary>
        public byte[] O_T_IOData
        {
            get
            {
                lock (_O_T_IOData_lock)
                {
                    return (byte[]) _O_T_IOData.Clone();
                }
            }
            set
            {
                lock (_O_T_IOData_lock)
                {
                    var length = value == null ? 0 : Math.Min(value.Length, _O_T_IOData.Length);
                    if (value != null)
                        Array.Copy(value, _O_T_IOData, length);

                    Array.Clear(_O_T_IOData, length, _O_T_IOData.Length - length);
                }
            }
        }

        /// <summary>
        /// Provides Access to the Class 1 Real-Time IO-Data Target -> Originator for Implicit Messaging
        /// </summary>
        public byte[] T_O_IOData
        {
            get
            {
                lock (_T_O_IOData_lock)
                {
                    return (byte[]) _T_O_IOData.Clone();
                }
            }
        }

        public event EventHandler<ImplicitMessageReceivedArgs> ImplicitMessageReceived;

        protected virtual void OnImplicitMessageReceived(ImplicitMessageReceivedArgs e)
        {
            ImplicitMessageReceived?.Invoke(this, e);
        }

        /// <summary>
        /// Converts a bytearray (received e.g. via getAttributeSingle) to ushort
        /// </summary>
        /// <param name="byteArray">bytearray to convert</param> 
        public static ushort ToUshort(byte[] byteArray)
        {
            var returnValue = (ushort)((byteArray[1] << 8) | byteArray[0]);
            return returnValue;
        }

        /// <summary>
        /// Converts a bytearray (received e.g. via getAttributeSingle) to uint
        /// </summary>
        /// <param name="byteArray">bytearray to convert</param> 
        public static uint ToUint(byte[] byteArray)
        {
            var returnValue = ((uint)byteArray[3] << 24) | ((uint)byteArray[2] << 16) | ((uint)byteArray[1] << 8) | byteArray[0];
            return returnValue;
        }

        /// <summary>
        /// Returns the "Bool" State of a byte Received via getAttributeSingle
        /// </summary>
        /// <param name="inputByte">byte to convert</param> 
        /// <param name="bitposition">bitposition to convert (First bit = bitposition 0)</param> 
        /// <returns>Converted bool value</returns>
        public static bool ToBool(byte inputByte, int bitposition)
        {
           
            return ((inputByte>>bitposition)&0x01) != 0 ? true : false;
        }

        public void Dispose()
        {
            this.stopUdpThread = true;
            this.udpClientReceiveClosed = true;
            ((IDisposable)this.client)?.Dispose();
            this.stream?.Dispose();
            ((IDisposable)this.udpClientReceive)?.Dispose();
        }
    }
}
