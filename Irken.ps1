function ConvertFrom-PacketOrderedDictionary
{
    param($packet_ordered_dictionary)

    ForEach($field in $packet_ordered_dictionary.Values)
    {
        $byte_array += $field
    }

    return $byte_array
}

#NetBIOS

function Get-PacketNetBIOSSessionService()
{
    param([Int]$packet_header_length,[Int]$packet_data_length)

    [Byte[]]$packet_netbios_session_service_length = [System.BitConverter]::GetBytes($packet_header_length + $packet_data_length)
    $packet_netbios_session_service_length = $packet_netbios_session_service_length[2..0]
    $packet_NetBIOS_session_service = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_NetBIOS_session_service.Add("NetBIOSSessionService_Message_Type",[Byte[]](0x00))
    $packet_NetBIOS_session_service.Add("NetBIOSSessionService_Length",[Byte[]]($packet_netbios_session_service_length))

    return $packet_NetBIOS_session_service
}

#SMB1

function Get-PacketSMBHeader()
{
    param([Byte[]]$packet_command,[Byte[]]$packet_flags,[Byte[]]$packet_flags2,[Byte[]]$packet_tree_ID,[Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID)

    $packet_SMB_header = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_header.Add("SMBHeader_Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
    $packet_SMB_header.Add("SMBHeader_Command",$packet_command)
    $packet_SMB_header.Add("SMBHeader_ErrorClass",[Byte[]](0x00))
    $packet_SMB_header.Add("SMBHeader_Reserved",[Byte[]](0x00))
    $packet_SMB_header.Add("SMBHeader_ErrorCode",[Byte[]](0x00,0x00))
    $packet_SMB_header.Add("SMBHeader_Flags",$packet_flags)
    $packet_SMB_header.Add("SMBHeader_Flags2",$packet_flags2)
    $packet_SMB_header.Add("SMBHeader_ProcessIDHigh",[Byte[]](0x00,0x00))
    $packet_SMB_header.Add("SMBHeader_Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB_header.Add("SMBHeader_Reserved2",[Byte[]](0x00,0x00))
    $packet_SMB_header.Add("SMBHeader_TreeID",$packet_tree_ID)
    $packet_SMB_header.Add("SMBHeader_ProcessID",$packet_process_ID)
    $packet_SMB_header.Add("SMBHeader_UserID",$packet_user_ID)
    $packet_SMB_header.Add("SMBHeader_MultiplexID",[Byte[]](0x00,0x00))

    return $packet_SMB_header
}

function Get-PacketSMBNegotiateProtocolRequest()
{
    param([String]$packet_version)

    if($packet_version -eq 'SMB1')
    {
        [Byte[]]$packet_byte_count = 0x0c,0x00
    }
    else
    {
        [Byte[]]$packet_byte_count = 0x22,0x00  
    }

    $packet_SMB_negotiate_protocol_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_negotiate_protocol_request.Add("SMBNegotiateProtocolRequest_WordCount",[Byte[]](0x00))
    $packet_SMB_negotiate_protocol_request.Add("SMBNegotiateProtocolRequest_ByteCount",$packet_byte_count)
    $packet_SMB_negotiate_protocol_request.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
    $packet_SMB_negotiate_protocol_request.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))

    if($packet_version -ne 'SMB1')
    {
        $packet_SMB_negotiate_protocol_request.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
        $packet_SMB_negotiate_protocol_request.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
        $packet_SMB_negotiate_protocol_request.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
        $packet_SMB_negotiate_protocol_request.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
    }

    return $packet_SMB_negotiate_protocol_request
}

function Get-PacketSMBSessionSetupAndXRequest()
{
    param([Byte[]]$packet_security_blob)

    [Byte[]]$packet_byte_count = [System.BitConverter]::GetBytes($packet_security_blob.Length)
    $packet_byte_count = $packet_byte_count[0,1]
    [Byte[]]$packet_security_blob_length = [System.BitConverter]::GetBytes($packet_security_blob.Length + 5)
    $packet_security_blob_length = $packet_security_blob_length[0,1]

    $packet_SMB_session_setup_andx_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_WordCount",[Byte[]](0x0c))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_AndXCommand",[Byte[]](0xff))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_Reserved",[Byte[]](0x00))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_MaxBuffer",[Byte[]](0xff,0xff))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_MaxMpxCount",[Byte[]](0x02,0x00))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_VCNumber",[Byte[]](0x01,0x00))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_SessionKey",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_SecurityBlobLength",$packet_byte_count)
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_Capabilities",[Byte[]](0x44,0x00,0x00,0x80))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_ByteCount",$packet_security_blob_length)
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_SecurityBlob",$packet_security_blob)
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_NativeOS",[Byte[]](0x00,0x00,0x00))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_NativeLANManage",[Byte[]](0x00,0x00))

    return $packet_SMB_session_setup_andx_request 
}

function Get-PacketSMBTreeConnectAndXRequest()
{
    param([Byte[]]$packet_path)

    [Byte[]]$packet_path_length = [System.BitConverter]::GetBytes($packet_path.Length + 7)
    $packet_path_length = $packet_path_length[0,1]

    $packet_SMB_tree_connect_andx_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_WordCount",[Byte[]](0x04))
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_AndXCommand",[Byte[]](0xff))
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_Reserved",[Byte[]](0x00))
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_Flags",[Byte[]](0x00,0x00))
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_PasswordLength",[Byte[]](0x01,0x00))
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_ByteCount",$packet_path_length)
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_Password",[Byte[]](0x00))
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_Tree",$packet_path)
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_Service",[Byte[]](0x3f,0x3f,0x3f,0x3f,0x3f,0x00))

    return $packet_SMB_tree_connect_andx_request
}

function Get-PacketSMBNTCreateAndXRequest()
{
    param([Byte[]]$packet_named_pipe)

    [Byte[]]$packet_named_pipe_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length)
    $packet_named_pipe_length = $packet_named_pipe_length[0,1]
    [Byte[]]$packet_file_name_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length - 1)
    $packet_file_name_length = $packet_file_name_length[0,1]

    $packet_SMB_NT_create_andx_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_WordCount",[Byte[]](0x18))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_AndXCommand",[Byte[]](0xff))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_Reserved",[Byte[]](0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_Reserved2",[Byte[]](0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_FileNameLen",$packet_file_name_length)
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_CreateFlags",[Byte[]](0x16,0x00,0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_RootFID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_AllocationSize",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_FileAttributes",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_ShareAccess",[Byte[]](0x07,0x00,0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_Disposition",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_CreateOptions",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_SecurityFlags",[Byte[]](0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_ByteCount",$packet_named_pipe_length)
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_Filename",$packet_named_pipe)

    return $packet_SMB_NT_create_andx_request
}

function Get-PacketSMBReadAndXRequest()
{
    $packet_SMB_read_andx_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_WordCount",[Byte[]](0x0a))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_AndXCommand",[Byte[]](0xff))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_Reserved",[Byte[]](0x00))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_FID",[Byte[]](0x00,0x40))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_MaxCountLow",[Byte[]](0x58,0x02))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_MinCount",[Byte[]](0x58,0x02))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_Unknown",[Byte[]](0xff,0xff,0xff,0xff))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_Remaining",[Byte[]](0x00,0x00))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_ByteCount",[Byte[]](0x00,0x00))

    return $packet_SMB_read_andx_request
}

function Get-PacketSMBWriteAndXRequest()
{
    param([Int]$packet_RPC_length)

    [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_RPC_length + 24)
    $packet_write_length = $packet_write_length[0,1]

    $packet_SMB_write_andx_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_WordCount",[Byte[]](0x0e))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_AndXCommand",[Byte[]](0xff))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_Reserved",[Byte[]](0x00))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_FID",[Byte[]](0x00,0x40))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_Offset",[Byte[]](0xea,0x03,0x00,0x00))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_Reserved2",[Byte[]](0xff,0xff,0xff,0xff))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_WriteMode",[Byte[]](0x08,0x00))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_Remaining",[Byte[]](0x50,0x00))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_DataLengthHigh",[Byte[]](0x00,0x00))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_DataLengthLow",$packet_write_length)
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_DataOffset",[Byte[]](0x3f,0x00))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_HighOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_ByteCount",$packet_write_length)

    return $packet_SMB_write_andx_request
}

function Get-PacketSMBCloseRequest()
{
    param ([Byte[]]$packet_file_ID)

    $packet_SMB_close_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_close_request.Add("SMBCloseRequest_WordCount",[Byte[]](0x03))
    $packet_SMB_close_request.Add("SMBCloseRequest_FID",$packet_file_ID)
    $packet_SMB_close_request.Add("SMBCloseRequest_LastWrite",[Byte[]](0xff,0xff,0xff,0xff))
    $packet_SMB_close_request.Add("SMBCloseRequest_ByteCount",[Byte[]](0x00,0x00))

    return $packet_SMB_close_request
}

function Get-PacketSMBTreeDisconnectRequest()
{
    $packet_SMB_tree_disconnect_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_tree_disconnect_request.Add("SMBTreeDisconnectRequest_WordCount",[Byte[]](0x00))
    $packet_SMB_tree_disconnect_request.Add("SMBTreeDisconnectRequest_ByteCount",[Byte[]](0x00,0x00))

    return $packet_SMB_tree_disconnect_request
}

function Get-PacketSMBLogoffAndXRequest()
{
    $packet_SMB_logoff_andx_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_logoff_andx_request.Add("SMBLogoffAndXRequest_WordCount",[Byte[]](0x02))
    $packet_SMB_logoff_andx_request.Add("SMBLogoffAndXRequest_AndXCommand",[Byte[]](0xff))
    $packet_SMB_logoff_andx_request.Add("SMBLogoffAndXRequest_Reserved",[Byte[]](0x00))
    $packet_SMB_logoff_andx_request.Add("SMBLogoffAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMB_logoff_andx_request.Add("SMBLogoffAndXRequest_ByteCount",[Byte[]](0x00,0x00))

    return $packet_SMB_logoff_andx_request
}

#SMB2

function Get-PacketSMB2Header()
{
    param([Byte[]]$packet_command,[Int]$packet_message_ID,[Byte[]]$packet_tree_ID,[Byte[]]$packet_session_ID)

    [Byte[]]$packet_message_ID = [System.BitConverter]::GetBytes($packet_message_ID) + 0x00,0x00,0x00,0x00

    $packet_SMB2_header = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_header.Add("SMB2Header_ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
    $packet_SMB2_header.Add("SMB2Header_StructureSize",[Byte[]](0x40,0x00))
    $packet_SMB2_header.Add("SMB2Header_CreditCharge",[Byte[]](0x01,0x00))
    $packet_SMB2_header.Add("SMB2Header_ChannelSequence",[Byte[]](0x00,0x00))
    $packet_SMB2_header.Add("SMB2Header_Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2_header.Add("SMB2Header_Command",$packet_command)
    $packet_SMB2_header.Add("SMB2Header_CreditRequest",[Byte[]](0x00,0x00))
    $packet_SMB2_header.Add("SMB2Header_Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_header.Add("SMB2Header_NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_header.Add("SMB2Header_MessageID",$packet_message_ID)
    $packet_SMB2_header.Add("SMB2Header_Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_header.Add("SMB2Header_TreeID",$packet_tree_ID)
    $packet_SMB2_header.Add("SMB2Header_SessionID",$packet_session_ID)
    $packet_SMB2_header.Add("SMB2Header_Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    return $packet_SMB2_header
}

function Get-PacketSMB2NegotiateProtocolRequest()
{
    $packet_SMB2_negotiate_protocol_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_StructureSize",[Byte[]](0x24,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_DialectCount",[Byte[]](0x02,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_SecurityMode",[Byte[]](0x01,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_Capabilities",[Byte[]](0x40,0x00,0x00,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_ClientGUID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_NegotiateContextOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_NegotiateContextCount",[Byte[]](0x00,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_Reserved2",[Byte[]](0x00,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_Dialect",[Byte[]](0x02,0x02))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_Dialect2",[Byte[]](0x10,0x02))

    return $packet_SMB2_negotiate_protocol_request
}

function Get-PacketSMB2SessionSetupRequest()
{
    param([Byte[]]$packet_security_blob)

    [Byte[]]$packet_security_blob_length = [System.BitConverter]::GetBytes($packet_security_blob.Length)
    $packet_security_blob_length = $packet_security_blob_length[0,1]

    $packet_SMB2_session_setup_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_StructureSize",[Byte[]](0x19,0x00))
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_Flags",[Byte[]](0x00))
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_SecurityMode",[Byte[]](0x01))
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_Capabilities",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_SecurityBufferOffset",[Byte[]](0x58,0x00))
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_SecurityBufferLength",$packet_security_blob_length)
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_PreviousSessionID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_Buffer",$packet_security_blob)

    return $packet_SMB2_session_setup_request 
}

function Get-PacketSMB2TreeConnectRequest()
{
    param([Byte[]]$packet_path)

    [Byte[]]$packet_path_length = [System.BitConverter]::GetBytes($packet_path.Length)
    $packet_path_length = $packet_path_length[0,1]

    $packet_SMB2_tree_connect_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_tree_connect_request.Add("SMB2TreeConnectRequest_StructureSize",[Byte[]](0x09,0x00))
    $packet_SMB2_tree_connect_request.Add("SMB2TreeConnectRequest_Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2_tree_connect_request.Add("SMB2TreeConnectRequest_PathOffset",[Byte[]](0x48,0x00))
    $packet_SMB2_tree_connect_request.Add("SMB2TreeConnectRequest_PathLength",$packet_path_length)
    $packet_SMB2_tree_connect_request.Add("SMB2TreeConnectRequest_Buffer",$packet_path)

    return $packet_SMB2_tree_connect_request
}

function Get-PacketSMB2CreateRequestFile()
{
    param([Byte[]]$packet_named_pipe)

    $packet_named_pipe_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length)
    $packet_named_pipe_length = $packet_named_pipe_length[0,1]

    $packet_SMB2_create_request_file = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_StructureSize",[Byte[]](0x39,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_Flags",[Byte[]](0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_RequestedOplockLevel",[Byte[]](0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_SMBCreateFlags",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_Reserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_DesiredAccess",[Byte[]](0x03,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_FileAttributes",[Byte[]](0x80,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_ShareAccess",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_CreateDisposition",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_CreateOptions",[Byte[]](0x40,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_NameOffset",[Byte[]](0x78,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_NameLength",$packet_named_pipe_length)
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_CreateContextsOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_CreateContextsLength",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_Buffer",$packet_named_pipe)

    return $packet_SMB2_create_request_file
}

function Get-PacketSMB2ReadRequest()
{
    param ([Byte[]]$packet_file_ID)

    $packet_SMB2_read_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_read_request.Add("SMB2ReadRequest_StructureSize",[Byte[]](0x31,0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_Padding",[Byte[]](0x50))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_Flags",[Byte[]](0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_Length",[Byte[]](0x00,0x00,0x10,0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_FileID",$packet_file_ID)
    $packet_SMB2_read_request.Add("SMB2ReadRequest_MinimumCount",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_ReadChannelInfoOffset",[Byte[]](0x00,0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_ReadChannelInfoLength",[Byte[]](0x00,0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_Buffer",[Byte[]](0x30))

    return $packet_SMB2_read_request
}

function Get-PacketSMB2WriteRequest()
{
    param([Byte[]]$packet_file_ID,[Int]$packet_RPC_length)

    [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_RPC_length + 24)

    $packet_SMB2_write_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_write_request.Add("SMB2WriteRequest_StructureSize",[Byte[]](0x31,0x00))
    $packet_SMB2_write_request.Add("SMB2WriteRequest_DataOffset",[Byte[]](0x70,0x00))
    $packet_SMB2_write_request.Add("SMB2WriteRequest_Length",$packet_write_length)
    $packet_SMB2_write_request.Add("SMB2WriteRequest_Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2_write_request.Add("SMB2WriteRequest_FileID",$packet_file_ID)
    $packet_SMB2_write_request.Add("SMB2WriteRequest_Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_write_request.Add("SMB2WriteRequest_RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_write_request.Add("SMB2WriteRequest_WriteChannelInfoOffset",[Byte[]](0x00,0x00))
    $packet_SMB2_write_request.Add("SMB2WriteRequest_WriteChannelInfoLength",[Byte[]](0x00,0x00))
    $packet_SMB2_write_request.Add("SMB2WriteRequest_Flags",[Byte[]](0x00,0x00,0x00,0x00))

    return $packet_SMB2_write_request
}

function Get-PacketSMB2CloseRequest()
{
    param ([Byte[]]$packet_file_ID)

    $packet_SMB2_close_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_close_request.Add("SMB2CloseRequest_StructureSize",[Byte[]](0x18,0x00))
    $packet_SMB2_close_request.Add("SMB2CloseRequest_Flags",[Byte[]](0x00,0x00))
    $packet_SMB2_close_request.Add("SMB2CloseRequest_Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_close_request.Add("SMB2CloseRequest_FileID",$packet_file_ID)

    return $packet_SMB2_close_request
}

function Get-PacketSMB2TreeDisconnectRequest()
{
    $packet_SMB2_tree_disconnect_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_tree_disconnect_request.Add("SMB2TreeDisconnectRequest_StructureSize",[Byte[]](0x04,0x00))
    $packet_SMB2_tree_disconnect_request.Add("SMB2TreeDisconnectRequest_Reserved",[Byte[]](0x00,0x00))

    return $packet_SMB2_tree_disconnect_request
}

function Get-PacketSMB2SessionLogoffRequest()
{
    $packet_SMB2_session_logoff_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_session_logoff_request.Add("SMB2SessionLogoffRequest_StructureSize",[Byte[]](0x04,0x00))
    $packet_SMB2_session_logoff_request.Add("SMB2SessionLogoffRequest_Reserved",[Byte[]](0x00,0x00))

    return $packet_SMB2_session_logoff_request
}

#NTLM

function Get-PacketNTLMSSPNegotiate()
{
    param([Byte[]]$packet_negotiate_flags,[Byte[]]$packet_version)

    [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes(32 + $packet_version.Length)
    $packet_NTLMSSP_length = $packet_NTLMSSP_length[0]
    [Byte[]]$packet_ASN_length_1 = $packet_NTLMSSP_length[0] + 32
    [Byte[]]$packet_ASN_length_2 = $packet_NTLMSSP_length[0] + 22
    [Byte[]]$packet_ASN_length_3 = $packet_NTLMSSP_length[0] + 20
    [Byte[]]$packet_ASN_length_4 = $packet_NTLMSSP_length[0] + 2

    $packet_NTLMSSPNegotiate = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InitialContextTokenID",[Byte[]](0x60)) # the ASN.1 key names are likely not all correct
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InitialcontextTokenLength",$packet_ASN_length_1)
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_ThisMechID",[Byte[]](0x06))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_ThisMechLength",[Byte[]](0x06))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_OID",[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenID",[Byte[]](0xa0))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenLength",$packet_ASN_length_2)
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenID2",[Byte[]](0x30))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenLength2",$packet_ASN_length_3)
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID",[Byte[]](0xa0))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength",[Byte[]](0x0e))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID2",[Byte[]](0x30))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength2",[Byte[]](0x0c))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID3",[Byte[]](0x06))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength3",[Byte[]](0x0a))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechType",[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTokenID",[Byte[]](0xa2))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTokenLength",$packet_ASN_length_4)
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NTLMSSPID",[Byte[]](0x04))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NTLMSSPLength",$packet_NTLMSSP_length)
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MessageType",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NegotiateFlags",$packet_negotiate_flags)
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    if($packet_version)
    {
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_Version",$packet_version)
    }

    return $packet_NTLMSSPNegotiate
}

function Get-PacketNTLMSSPAuth()
{
    param([Byte[]]$packet_NTLM_response)

    [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes($packet_NTLM_response.Length)
    $packet_NTLMSSP_length = $packet_NTLMSSP_length[1,0]
    [Byte[]]$packet_ASN_length_1 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 12)
    $packet_ASN_length_1 = $packet_ASN_length_1[1,0]
    [Byte[]]$packet_ASN_length_2 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 8)
    $packet_ASN_length_2 = $packet_ASN_length_2[1,0]
    [Byte[]]$packet_ASN_length_3 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 4)
    $packet_ASN_length_3 = $packet_ASN_length_3[1,0]

    $packet_NTLMSSPAuth = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID",[Byte[]](0xa1,0x82))
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength",$packet_ASN_length_1)
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID2",[Byte[]](0x30,0x82))
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength2",$packet_ASN_length_2)
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID3",[Byte[]](0xa2,0x82))
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength3",$packet_ASN_length_3)
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMSSPID",[Byte[]](0x04,0x82))
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMSSPLength",$packet_NTLMSSP_length)
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMResponse",$packet_NTLM_response)

    return $packet_NTLMSSPAuth
}

#RPC

function Get-PacketRPCBind()
{
    param([Int]$packet_call_ID,[Byte[]]$packet_max_frag,[Byte[]]$packet_num_ctx_items,[Byte[]]$packet_context_ID,[Byte[]]$packet_UUID,[Byte[]]$packet_UUID_version)

    [Byte[]]$packet_call_ID_bytes = [System.BitConverter]::GetBytes($packet_call_ID)

    $packet_RPCBind = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCBind.Add("RPCBind_Version",[Byte[]](0x05))
    $packet_RPCBind.Add("RPCBind_VersionMinor",[Byte[]](0x00))
    $packet_RPCBind.Add("RPCBind_PacketType",[Byte[]](0x0b))
    $packet_RPCBind.Add("RPCBind_PacketFlags",[Byte[]](0x03))
    $packet_RPCBind.Add("RPCBind_DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCBind.Add("RPCBind_FragLength",[Byte[]](0x48,0x00))
    $packet_RPCBind.Add("RPCBind_AuthLength",[Byte[]](0x00,0x00))
    $packet_RPCBind.Add("RPCBind_CallID",$packet_call_ID_bytes)
    $packet_RPCBind.Add("RPCBind_MaxXmitFrag",[Byte[]](0xb8,0x10))
    $packet_RPCBind.Add("RPCBind_MaxRecvFrag",[Byte[]](0xb8,0x10))
    $packet_RPCBind.Add("RPCBind_AssocGroup",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_RPCBind.Add("RPCBind_NumCtxItems",$packet_num_ctx_items)
    $packet_RPCBind.Add("RPCBind_Unknown",[Byte[]](0x00,0x00,0x00))
    $packet_RPCBind.Add("RPCBind_ContextID",$packet_context_ID)
    $packet_RPCBind.Add("RPCBind_NumTransItems",[Byte[]](0x01))
    $packet_RPCBind.Add("RPCBind_Unknown2",[Byte[]](0x00))
    $packet_RPCBind.Add("RPCBind_Interface",$packet_UUID)
    $packet_RPCBind.Add("RPCBind_InterfaceVer",$packet_UUID_version)
    $packet_RPCBind.Add("RPCBind_InterfaceVerMinor",[Byte[]](0x00,0x00))
    $packet_RPCBind.Add("RPCBind_TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    $packet_RPCBind.Add("RPCBind_TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))

    if($packet_num_ctx_items[0] -eq 2)
    {
        $packet_RPCBind.Add("RPCBind_ContextID2",[Byte[]](0x01,0x00))
        $packet_RPCBind.Add("RPCBind_NumTransItems2",[Byte[]](0x01))
        $packet_RPCBind.Add("RPCBind_Unknown3",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_Interface2",[Byte[]](0xc4,0xfe,0xfc,0x99,0x60,0x52,0x1b,0x10,0xbb,0xcb,0x00,0xaa,0x00,0x21,0x34,0x7a))
        $packet_RPCBind.Add("RPCBind_InterfaceVer2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("RPCBind_InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("RPCBind_TransferSyntax2",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
    }
    elseif($packet_num_ctx_items[0] -eq 3)
    {
        $packet_RPCBind.Add("RPCBind_ContextID2",[Byte[]](0x01,0x00))
        $packet_RPCBind.Add("RPCBind_NumTransItems2",[Byte[]](0x01))
        $packet_RPCBind.Add("RPCBind_Unknown3",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_Interface2",[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
        $packet_RPCBind.Add("RPCBind_InterfaceVer2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("RPCBind_InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("RPCBind_TransferSyntax2",[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
        $packet_RPCBind.Add("RPCBind_TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_ContextID3",[Byte[]](0x02,0x00))
        $packet_RPCBind.Add("RPCBind_NumTransItems3",[Byte[]](0x01))
        $packet_RPCBind.Add("RPCBind_Unknown4",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_Interface3",[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
        $packet_RPCBind.Add("RPCBind_InterfaceVer3",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("RPCBind_InterfaceVerMinor3",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("RPCBind_TransferSyntax3",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_TransferSyntaxVer3",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_AuthType",[Byte[]](0x0a))
        $packet_RPCBind.Add("RPCBind_AuthLevel",[Byte[]](0x04))
        $packet_RPCBind.Add("RPCBind_AuthPadLength",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_AuthReserved",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_ContextID4",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $packet_RPCBind.Add("RPCBind_MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
        $packet_RPCBind.Add("RPCBind_CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
    }

    if($packet_call_ID -eq 3)
    {
        $packet_RPCBind.Add("RPCBind_AuthType",[Byte[]](0x0a))
        $packet_RPCBind.Add("RPCBind_AuthLevel",[Byte[]](0x02))
        $packet_RPCBind.Add("RPCBind_AuthPadLength",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_AuthReserved",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_ContextID3",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $packet_RPCBind.Add("RPCBind_MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
        $packet_RPCBind.Add("RPCBind_CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
    }

    return $packet_RPCBind
}

function Get-PacketRPCRequest()
{
    param([Byte[]]$packet_flags,[Int]$packet_service_length,[Int]$packet_auth_length,[Int]$packet_auth_padding,[Byte[]]$packet_call_ID,[Byte[]]$packet_context_ID,[Byte[]]$packet_opnum,[Byte[]]$packet_object_UUID)

    if($packet_auth_length -gt 0)
    {
        $packet_full_auth_length = $packet_auth_length + $packet_auth_padding + 8
    }

    [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_service_length + 24 + $packet_full_auth_length + $packet_object_UUID.Length)
    [Byte[]]$packet_frag_length = $packet_write_length[0,1]
    [Byte[]]$packet_alloc_hint = [System.BitConverter]::GetBytes($packet_service_length)
    [Byte[]]$packet_auth_length = [System.BitConverter]::GetBytes($packet_auth_length)
    $packet_auth_length = $packet_auth_length[0,1]

    $packet_RPCRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCRequest.Add("RPCRequest_Version",[Byte[]](0x05))
    $packet_RPCRequest.Add("RPCRequest_VersionMinor",[Byte[]](0x00))
    $packet_RPCRequest.Add("RPCRequest_PacketType",[Byte[]](0x00))
    $packet_RPCRequest.Add("RPCRequest_PacketFlags",$packet_flags)
    $packet_RPCRequest.Add("RPCRequest_DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCRequest.Add("RPCRequest_FragLength",$packet_frag_length)
    $packet_RPCRequest.Add("RPCRequest_AuthLength",$packet_auth_length)
    $packet_RPCRequest.Add("RPCRequest_CallID",$packet_call_ID)
    $packet_RPCRequest.Add("RPCRequest_AllocHint",$packet_alloc_hint)
    $packet_RPCRequest.Add("RPCRequest_ContextID",$packet_context_ID)
    $packet_RPCRequest.Add("RPCRequest_Opnum",$packet_opnum)

    if($packet_object_UUID.Length)
    {
        $packet_RPCRequest.Add("RPCRequest_ObjectUUID",$packet_object_UUID)
    }

    return $packet_RPCRequest
}

#SCM

function Get-PacketSCMOpenSCManagerW()
{
    param ([Byte[]]$packet_service,[Byte[]]$packet_service_length)

    [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_service.Length + 92)
    [Byte[]]$packet_frag_length = $packet_write_length[0,1]
    [Byte[]]$packet_alloc_hint = [System.BitConverter]::GetBytes($packet_service.Length + 68)
    $packet_referent_ID1 = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    $packet_referent_ID1 = $packet_referent_ID1.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $packet_referent_ID1 += 0x00,0x00
    $packet_referent_ID2 = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    $packet_referent_ID2 = $packet_referent_ID2.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $packet_referent_ID2 += 0x00,0x00

    $packet_SCMOpenSCManagerW = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_ReferentID",$packet_referent_ID1)
    $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_MaxCount",$packet_service_length)
    $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_ActualCount",$packet_service_length)
    $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName",$packet_service)
    $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_ReferentID",$packet_referent_ID2)
    $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_NameMaxCount",[Byte[]](0x0f,0x00,0x00,0x00))
    $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_NameOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_NameActualCount",[Byte[]](0x0f,0x00,0x00,0x00))
    $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database",[Byte[]](0x53,0x00,0x65,0x00,0x72,0x00,0x76,0x00,0x69,0x00,0x63,0x00,0x65,0x00,0x73,0x00,0x41,0x00,0x63,0x00,0x74,0x00,0x69,0x00,0x76,0x00,0x65,0x00,0x00,0x00))
    $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Unknown",[Byte[]](0xbf,0xbf))
    $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_AccessMask",[Byte[]](0x3f,0x00,0x00,0x00))
    
    return $packet_SCMOpenSCManagerW
}

function Get-PacketSCMCreateServiceW()
{
    param([Byte[]]$packet_context_handle,[Byte[]]$packet_service,[Byte[]]$packet_service_length,
            [Byte[]]$packet_command,[Byte[]]$packet_command_length)
                
    $packet_referent_ID = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    $packet_referent_ID = $packet_referent_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $packet_referent_ID += 0x00,0x00

    $packet_SCMCreateServiceW = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ContextHandle",$packet_context_handle)
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName_MaxCount",$packet_service_length)
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName_ActualCount",$packet_service_length)
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName",$packet_service)
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_ReferentID",$packet_referent_ID)
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_MaxCount",$packet_service_length)
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_ActualCount",$packet_service_length)
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName",$packet_service)
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_AccessMask",[Byte[]](0xff,0x01,0x0f,0x00))
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceType",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceStartType",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceErrorControl",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName_MaxCount",$packet_command_length)
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName_ActualCount",$packet_command_length)
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName",$packet_command)
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_TagID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DependSize",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer3",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer4",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("SCMCreateServiceW_PasswordSize",[Byte[]](0x00,0x00,0x00,0x00))

    return $packet_SCMCreateServiceW
}

function Get-PacketSCMStartServiceW()
{
    param([Byte[]]$packet_context_handle)

    $packet_SCMStartServiceW = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SCMStartServiceW.Add("SCMStartServiceW_ContextHandle",$packet_context_handle)
    $packet_SCMStartServiceW.Add("SCMStartServiceW_Unknown",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    return $packet_SCMStartServiceW
}

function Get-PacketSCMDeleteServiceW()
{
    param([Byte[]]$packet_context_handle)

    $packet_SCMDeleteServiceW = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SCMDeleteServiceW.Add("SCMDeleteServiceW_ContextHandle",$packet_context_handle)

    return $packet_SCMDeleteServiceW
}

function Get-PacketSCMCloseServiceHandle()
{
    param([Byte[]]$packet_context_handle)

    $packet_SCM_CloseServiceW = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SCM_CloseServiceW.Add("SCMCloseServiceW_ContextHandle",$packet_context_handle)

    return $packet_SCM_CloseServiceW
}

function Get-PacketRPCAUTH3()
{
    param([Byte[]]$packet_NTLMSSP)

    [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes($packet_NTLMSSP.Length)
    $packet_NTLMSSP_length = $packet_NTLMSSP_length[0,1]
    [Byte[]]$packet_RPC_length = [System.BitConverter]::GetBytes($packet_NTLMSSP.Length + 28)
    $packet_RPC_length = $packet_RPC_length[0,1]

    $packet_RPCAuth3 = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCAuth3.Add("RPCAUTH3_Version",[Byte[]](0x05))
    $packet_RPCAuth3.Add("RPCAUTH3_VersionMinor",[Byte[]](0x00))
    $packet_RPCAuth3.Add("RPCAUTH3_PacketType",[Byte[]](0x10))
    $packet_RPCAuth3.Add("RPCAUTH3_PacketFlags",[Byte[]](0x03))
    $packet_RPCAuth3.Add("RPCAUTH3_DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCAuth3.Add("RPCAUTH3_FragLength",$packet_RPC_length)
    $packet_RPCAuth3.Add("RPCAUTH3_AuthLength",$packet_NTLMSSP_length)
    $packet_RPCAuth3.Add("RPCAUTH3_CallID",[Byte[]](0x03,0x00,0x00,0x00))
    $packet_RPCAuth3.Add("RPCAUTH3_MaxXmitFrag",[Byte[]](0xd0,0x16))
    $packet_RPCAuth3.Add("RPCAUTH3_MaxRecvFrag",[Byte[]](0xd0,0x16))
    $packet_RPCAuth3.Add("RPCAUTH3_AuthType",[Byte[]](0x0a))
    $packet_RPCAuth3.Add("RPCAUTH3_AuthLevel",[Byte[]](0x02))
    $packet_RPCAuth3.Add("RPCAUTH3_AuthPadLength",[Byte[]](0x00))
    $packet_RPCAuth3.Add("RPCAUTH3_AuthReserved",[Byte[]](0x00))
    $packet_RPCAuth3.Add("RPCAUTH3_ContextID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_RPCAuth3.Add("RPCAUTH3_NTLMSSP",$packet_NTLMSSP)

    return $packet_RPCAuth3
}

function Get-PacketRPCRequest()
{
    param([Byte[]]$packet_flags,[Int]$packet_service_length,[Int]$packet_auth_length,[Int]$packet_auth_padding,[Byte[]]$packet_call_ID,[Byte[]]$packet_context_ID,[Byte[]]$packet_opnum,[Byte[]]$packet_object_UUID)

    if($packet_auth_length -gt 0)
    {
        $packet_full_auth_length = $packet_auth_length + $packet_auth_padding + 8
    }

    [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_service_length + 24 + $packet_full_auth_length + $packet_object_UUID.Length)
    [Byte[]]$packet_frag_length = $packet_write_length[0,1]
    [Byte[]]$packet_alloc_hint = [System.BitConverter]::GetBytes($packet_service_length)
    [Byte[]]$packet_auth_length = [System.BitConverter]::GetBytes($packet_auth_length)
    $packet_auth_length = $packet_auth_length[0,1]

    $packet_RPCRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCRequest.Add("RPCRequest_Version",[Byte[]](0x05))
    $packet_RPCRequest.Add("RPCRequest_VersionMinor",[Byte[]](0x00))
    $packet_RPCRequest.Add("RPCRequest_PacketType",[Byte[]](0x00))
    $packet_RPCRequest.Add("RPCRequest_PacketFlags",$packet_flags)
    $packet_RPCRequest.Add("RPCRequest_DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCRequest.Add("RPCRequest_FragLength",$packet_frag_length)
    $packet_RPCRequest.Add("RPCRequest_AuthLength",$packet_auth_length)
    $packet_RPCRequest.Add("RPCRequest_CallID",$packet_call_ID)
    $packet_RPCRequest.Add("RPCRequest_AllocHint",$packet_alloc_hint)
    $packet_RPCRequest.Add("RPCRequest_ContextID",$packet_context_ID)
    $packet_RPCRequest.Add("RPCRequest_Opnum",$packet_opnum)

    if($packet_object_UUID.Length)
    {
        $packet_RPCRequest.Add("RPCRequest_ObjectUUID",$packet_object_UUID)
    }

    return $packet_RPCRequest
}

function Get-PacketRPCAlterContext()
{
    param([Byte[]]$packet_assoc_group,[Byte[]]$packet_call_ID,[Byte[]]$packet_context_ID,[Byte[]]$packet_interface_UUID)

    $packet_RPCAlterContext = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCAlterContext.Add("RPCAlterContext_Version",[Byte[]](0x05))
    $packet_RPCAlterContext.Add("RPCAlterContext_VersionMinor",[Byte[]](0x00))
    $packet_RPCAlterContext.Add("RPCAlterContext_PacketType",[Byte[]](0x0e))
    $packet_RPCAlterContext.Add("RPCAlterContext_PacketFlags",[Byte[]](0x03))
    $packet_RPCAlterContext.Add("RPCAlterContext_DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCAlterContext.Add("RPCAlterContext_FragLength",[Byte[]](0x48,0x00))
    $packet_RPCAlterContext.Add("RPCAlterContext_AuthLength",[Byte[]](0x00,0x00))
    $packet_RPCAlterContext.Add("RPCAlterContext_CallID",$packet_call_ID)
    $packet_RPCAlterContext.Add("RPCAlterContext_MaxXmitFrag",[Byte[]](0xd0,0x16))
    $packet_RPCAlterContext.Add("RPCAlterContext_MaxRecvFrag",[Byte[]](0xd0,0x16))
    $packet_RPCAlterContext.Add("RPCAlterContext_AssocGroup",$packet_assoc_group)
    $packet_RPCAlterContext.Add("RPCAlterContext_NumCtxItems",[Byte[]](0x01))
    $packet_RPCAlterContext.Add("RPCAlterContext_Unknown",[Byte[]](0x00,0x00,0x00))
    $packet_RPCAlterContext.Add("RPCAlterContext_ContextID",$packet_context_ID)
    $packet_RPCAlterContext.Add("RPCAlterContext_NumTransItems",[Byte[]](0x01))
    $packet_RPCAlterContext.Add("RPCAlterContext_Unknown2",[Byte[]](0x00))
    $packet_RPCAlterContext.Add("RPCAlterContext_Interface",$packet_interface_UUID)
    $packet_RPCAlterContext.Add("RPCAlterContext_InterfaceVer",[Byte[]](0x00,0x00))
    $packet_RPCAlterContext.Add("RPCAlterContext_InterfaceVerMinor",[Byte[]](0x00,0x00))
    $packet_RPCAlterContext.Add("RPCAlterContext_TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    $packet_RPCAlterContext.Add("RPCAlterContext_TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))

    return $packet_RPCAlterContext
}

function Get-PacketNTLMSSPVerifier()
{
    param([Int]$packet_auth_padding,[Byte[]]$packet_auth_level,[Byte[]]$packet_sequence_number)

    $packet_NTLMSSPVerifier = New-Object System.Collections.Specialized.OrderedDictionary

    if($packet_auth_padding -eq 4)
    {
        $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthPadding",[Byte[]](0x00,0x00,0x00,0x00))
        [Byte[]]$packet_auth_pad_length = 0x04
    }
    elseif($packet_auth_padding -eq 8)
    {
        $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthPadding",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        [Byte[]]$packet_auth_pad_length = 0x08
    }
    elseif($packet_auth_padding -eq 12)
    {
        $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthPadding",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        [Byte[]]$packet_auth_pad_length = 0x0c
    }
    else
    {
        [Byte[]]$packet_auth_pad_length = 0x00
    }

    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthType",[Byte[]](0x0a))
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthLevel",$packet_auth_level)
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthPadLen",$packet_auth_pad_length)
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthReserved",[Byte[]](0x00))
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthContextID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_NTLMSSPVerifierVersionNumber",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_NTLMSSPVerifierChecksum",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_NTLMSSPVerifierSequenceNumber",$packet_sequence_number)

    return $packet_NTLMSSPVerifier
}

function Get-PacketDCOMRemQueryInterface()
{
    param([Byte[]]$packet_causality_ID,[Byte[]]$packet_IPID,[Byte[]]$packet_IID)

    $packet_DCOMRemQueryInterface = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_VersionMajor",[Byte[]](0x05,0x00))
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_VersionMinor",[Byte[]](0x07,0x00))
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_CausalityID",$packet_causality_ID)
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_IPID",$packet_IPID)
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Refs",[Byte[]](0x05,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_IIDs",[Byte[]](0x01,0x00))
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Unknown",[Byte[]](0x00,0x00,0x01,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_IID",$packet_IID)

    return $packet_DCOMRemQueryInterface
}

function Get-PacketDCOMRemRelease()
{
    param([Byte[]]$packet_causality_ID,[Byte[]]$packet_IPID,[Byte[]]$packet_IPID2)

    $packet_DCOMRemRelease = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_DCOMRemRelease.Add("DCOMRemRelease_VersionMajor",[Byte[]](0x05,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_VersionMinor",[Byte[]](0x07,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_CausalityID",$packet_causality_ID)
    $packet_DCOMRemRelease.Add("DCOMRemRelease_Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_Unknown",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_InterfaceRefs",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_IPID",$packet_IPID)
    $packet_DCOMRemRelease.Add("DCOMRemRelease_PublicRefs",[Byte[]](0x05,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_PrivateRefs",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_IPID2",$packet_IPID2)
    $packet_DCOMRemRelease.Add("DCOMRemRelease_PublicRefs2",[Byte[]](0x05,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_PrivateRefs2",[Byte[]](0x00,0x00,0x00,0x00))

    return $packet_DCOMRemRelease
}

function Get-PacketDCOMRemoteCreateInstance()
{
    param([Byte[]]$packet_causality_ID,[String]$packet_target)

    [Byte[]]$packet_target_unicode = [System.Text.Encoding]::Unicode.GetBytes($packet_target)
    [Byte[]]$packet_target_length = [System.BitConverter]::GetBytes($packet_target.Length + 1)
    $packet_target_unicode += ,0x00 * (([Math]::Truncate($packet_target_unicode.Length / 8 + 1) * 8) - $packet_target_unicode.Length)
    [Byte[]]$packet_cntdata = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 720)
    [Byte[]]$packet_size = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 680)
    [Byte[]]$packet_total_size = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 664)
    [Byte[]]$packet_private_header = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 40) + 0x00,0x00,0x00,0x00
    [Byte[]]$packet_property_data_size = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 56)

    $packet_DCOMRemoteCreateInstance = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMVersionMajor",[Byte[]](0x05,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMVersionMinor",[Byte[]](0x07,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMFlags",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMCausalityID",$packet_causality_ID)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_Unknown",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_Unknown2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_Unknown3",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_Unknown4",$packet_cntdata)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCntData",$packet_cntdata)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesOBJREFSignature",[Byte[]](0x4d,0x45,0x4f,0x57))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesOBJREFFlags",[Byte[]](0x04,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesOBJREFIID",[Byte[]](0xa2,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFCLSID",[Byte[]](0x38,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFCBExtension",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFSize",$packet_size)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesTotalSize",$packet_total_size)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderPrivateHeader",[Byte[]](0xb0,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderTotalSize",$packet_total_size)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCustomHeaderSize",[Byte[]](0xc0,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesDestinationContext",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesNumActivationPropertyStructs",[Byte[]](0x06,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsInfoClsid",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesNULLPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrMaxCount",[Byte[]](0x06,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid",[Byte[]](0xb9,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid2",[Byte[]](0xab,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid3",[Byte[]](0xa5,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid4",[Byte[]](0xa6,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid5",[Byte[]](0xa4,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid6",[Byte[]](0xaa,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrMaxCount",[Byte[]](0x06,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize",[Byte[]](0x68,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize2",[Byte[]](0x58,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize3",[Byte[]](0x90,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize4",$packet_property_data_size)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize5",[Byte[]](0x20,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize6",[Byte[]](0x30,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPrivateHeader",[Byte[]](0x58,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesSessionID",[Byte[]](0xff,0xff,0xff,0xff))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesRemoteThisSessionID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesClientImpersonating",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionIDPresent",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesDefaultAuthnLevel",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionGuid",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesProcessRequestFlags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesOriginalClassContext",[Byte[]](0x14,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesFlags",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesReserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesUnusedBuffer",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoPrivateHeader",[Byte[]](0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiatedObjectClsId",[Byte[]](0x5e,0xf0,0xc3,0x8b,0x6b,0xd8,0xd0,0x11,0xa0,0x75,0x00,0xc0,0x4f,0xb6,0x88,0x20))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoClassContext",[Byte[]](0x14,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoActivationFlags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoFlagsSurrogate",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInterfaceIdCount",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiationFlag",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtr",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationEntirePropertySize",[Byte[]](0x58,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMajor",[Byte[]](0x05,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMinor",[Byte[]](0x07,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtrMaxCount",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIds",[Byte[]](0x18,0xad,0x09,0xf3,0x6a,0xd8,0xd0,0x11,0xa0,0x75,0x00,0xc0,0x4f,0xb6,0x88,0x20))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsUnusedBuffer",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoPrivateHeader",[Byte[]](0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientOk",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved3",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextUnknown",[Byte[]](0x60,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextCntData",[Byte[]](0x60,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFSignature",[Byte[]](0x4d,0x45,0x4f,0x57))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFFlags",[Byte[]](0x04,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFIID",[Byte[]](0xc0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCLSID",[Byte[]](0x3b,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCBExtension",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFSize",[Byte[]](0x30,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoUnusedBuffer",[Byte[]](0x01,0x00,0x01,0x00,0x63,0x2c,0x80,0x2a,0xa5,0xd2,0xaf,0xdd,0x4d,0xc4,0xbb,0x37,0x4d,0x37,0x76,0xd7,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoPrivateHeader",$packet_private_header)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoAuthenticationFlags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoPtrReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameMaxCount",$packet_target_length)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameActualCount",$packet_target_length)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameString",$packet_target_unicode)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoPrivateHeader",[Byte[]](0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoProcessID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoApartmentID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoContextID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoPrivateHeader",[Byte[]](0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestClientImpersonationLevel",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestNumProtocolSequences",[Byte[]](0x01,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestUnknown",[Byte[]](0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrMaxCount",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrProtocolSeq",[Byte[]](0x07,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoUnusedBuffer",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00))

    return $packet_DCOMRemoteCreateInstance
}