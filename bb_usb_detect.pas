unit bb_usb_detect;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, StrUtils;

type
  TBBInterface = record
    Name: string;
    MAC: string;
    IPv4: string;       // computer
    IPv4Phone: string;  // phone
    IPv6: string;       // computer
    IPv6Phone: string;  // phone
  end;

  TBBInterfaceList = array of TBBInterface;

function GetBlackBerryInterfaces: TBBInterfaceList;

implementation

{$IFDEF UNIX}
uses
  ctypes, BaseUnix, Unix, Sockets;
const
  INET6_ADDRSTRLEN = 46;
{$ENDIF}
{$IFDEF WINDOWS}
uses
  Windows, JwaIpHlpApi, JwaIpTypes, JwaWinsock2;
{$ENDIF}

// Common functions for all platforms
function IsAPIPAAddress(const IP: string): boolean;
begin
  Result := (Length(IP) >= 8) and (Copy(IP, 1, 8) = '169.254.');
end;

function IsLinkLocalIPv6(const IP: string): boolean;
begin
  Result := (Length(IP) >= 4) and (LowerCase(Copy(IP, 1, 4)) = 'fe80');
end;

// Calculate phone IP for IPv4 with proper subnet handling
function IPv4PhoneIP(const IP, Netmask: string): string;
var
  IPParts, MaskParts: TStringArray;
  IPInt, MaskInt, NetBase, Broadcast, PhoneInt: cardinal;
  i: integer;
begin
  Result := '';
  try
    IPParts := SplitString(IP, '.');
    MaskParts := SplitString(Netmask, '.');

    if (Length(IPParts) <> 4) or (Length(MaskParts) <> 4) then
      Exit;

    IPInt := 0;
    MaskInt := 0;
    for i := 0 to 3 do
    begin
      IPInt := (IPInt shl 8) + cardinal(StrToIntDef(IPParts[i], 0));
      MaskInt := (MaskInt shl 8) + cardinal(StrToIntDef(MaskParts[i], 0));
    end;

    NetBase := IPInt and MaskInt;
    Broadcast := NetBase or (not MaskInt);

    // Choose phone IP based on available addresses
    if IPInt = NetBase + 1 then
      PhoneInt := NetBase + 2  // If computer is .1, phone is .2
    else if IPInt = NetBase + 2 then
      PhoneInt := NetBase + 1  // If computer is .2, phone is .1
    else if IPInt > NetBase then
      PhoneInt := IPInt - 1    // Default: phone is one less
    else
      PhoneInt := NetBase + 1; // Fallback

    // Ensure phone IP is within valid range
    if (PhoneInt <= NetBase) or (PhoneInt >= Broadcast) then
      Exit;

    Result := Format('%d.%d.%d.%d', [(PhoneInt shr 24) and $FF, (PhoneInt shr 16) and
      $FF, (PhoneInt shr 8) and $FF, PhoneInt and $FF]);
  except
    Result := '';
  end;
end;

// Calculate IPv6 phone IP (modify interface identifier)
function IPv6PhoneIP(const IP: string): string;
var
  Parts: TStringArray;
  LastPart: string;
  LastValue, NewValue: integer;
begin
  Result := '';
  try
    if Pos('::', IP) > 0 then
      Exit; // Skip compressed IPv6 addresses for simplicity

    Parts := SplitString(IP, ':');
    if Length(Parts) < 8 then
      Exit;

    LastPart := Parts[High(Parts)];
    LastValue := StrToInt('$' + LastPart);

    // Modify the interface identifier (last 64 bits)
    if LastValue > 1 then
      NewValue := LastValue - 1
    else
      NewValue := LastValue + 1;

    Parts[High(Parts)] := LowerCase(IntToHex(NewValue, Length(LastPart)));
    Result.Join(':', Parts);
  except
    Result := '';
  end;
end;

procedure ProcessInterface(var Interfaces: TBBInterfaceList; const IfName, MAC: string;
  const IPv4, IPv4Mask, IPv6: string);
var
  Idx: integer;
  Found: boolean;
begin
  // Skip invalid interfaces
  if (IfName = '') or (MAC = '') then Exit;
  if not (IsAPIPAAddress(IPv4) or IsLinkLocalIPv6(IPv6)) then Exit;

  // Find existing interface or create new one
  Found := False;
  Idx := 0;

  for Idx := 0 to High(Interfaces) do
  begin
    if Interfaces[Idx].Name = IfName then
    begin
      Found := True;
      Break;
    end;
  end;

  if not Found then
  begin
    SetLength(Interfaces, Length(Interfaces) + 1);
    Idx := High(Interfaces);
    Interfaces[Idx].Name := IfName;
    Interfaces[Idx].MAC := MAC;
    Interfaces[Idx].IPv4 := '';
    Interfaces[Idx].IPv4Phone := '';
    Interfaces[Idx].IPv6 := '';
    Interfaces[Idx].IPv6Phone := '';
  end;

  // Update IP addresses
  if IsAPIPAAddress(IPv4) then
  begin
    Interfaces[Idx].IPv4 := IPv4;
    Interfaces[Idx].IPv4Phone := IPv4PhoneIP(IPv4, IPv4Mask);
  end;

  if IsLinkLocalIPv6(IPv6) then
  begin
    Interfaces[Idx].IPv6 := IPv6;
    Interfaces[Idx].IPv6Phone := IPv6PhoneIP(IPv6);
  end;
end;

{$IFDEF UNIX}
type
  sa_family_t = cuint16;

  Psockaddr = ^sockaddr;
  sockaddr = record
    sa_family: sa_family_t;
    sa_data: array[0..13] of cchar;
  end;

  Psockaddr_in = ^sockaddr_in;
  sockaddr_in = record
    sin_family: sa_family_t;
    sin_port: cuint16;
    sin_addr: cuint32;
    sin_zero: array[0..7] of cchar;
  end;

  Psockaddr_in6 = ^sockaddr_in6;
  sockaddr_in6 = record
    sin6_family: sa_family_t;
    sin6_port: cuint16;
    sin6_flowinfo: cuint32;
    sin6_addr: array[0..15] of byte;
    sin6_scope_id: cuint32;
  end;

  {$IFDEF DARWIN}
  Psockaddr_dl = ^sockaddr_dl;
  sockaddr_dl = record
    sdl_len: cuchar;
    sdl_family: cuchar;
    sdl_index: cushort;
    sdl_type: cuchar;
    sdl_nlen: cuchar;
    sdl_alen: cuchar;
    sdl_slen: cuchar;
    sdl_data: array[0..11] of cchar;
  end;
  {$ENDIF}

  PIfAddrs = ^TIfAddrs;
  TIfAddrs = record
    ifa_next: PIfAddrs;
    ifa_name: PChar;
    ifa_flags: cuint32;
    ifa_addr: Psockaddr;
    ifa_netmask: Psockaddr;
    ifa_dstaddr: Psockaddr;
    ifa_data: Pointer;
  end;

const
  IFF_UP = $1;
  AF_INET = 2;
  AF_INET6 = 10;
  {$IFDEF DARWIN}
  AF_LINK = 18;
  libc = 'libc.dylib';
  {$ELSE}
  libc = 'c';
  {$ENDIF}

function getifaddrs(var ifap: PIfAddrs): cint; cdecl; external libc name 'getifaddrs';
procedure freeifaddrs(ifap: PIfAddrs); cdecl; external libc name 'freeifaddrs';
{$IFNDEF DARWIN}
function inet_ntop(af: cint; src: pointer; dst: pchar; size: socklen_t): pchar; cdecl; external libc name 'inet_ntop';
{$ENDIF}

function NetAddrToStr(const Addr: cuint32): string;
begin
  Result := Format('%d.%d.%d.%d',
    [Addr and $FF,
     (Addr shr 8) and $FF,
     (Addr shr 16) and $FF,
     (Addr shr 24) and $FF]);
end;

function IPv6AddrToStr(const Addr: array of byte): string;
{$IFDEF DARWIN}
var
  i: Integer;
begin
  Result := '';
  for i := 0 to 15 do
  begin
    if i > 0 then
    begin
      if (i mod 2) = 0 then Result := Result + ':';
    end;
    Result := Result + IntToHex(Addr[i], 2);
  end;
  // Simple compression of consecutive zeros (basic implementation)
  Result := StringReplace(Result, ':0000:', '::', [rfReplaceAll]);
  Result := StringReplace(Result, ':000', ':', [rfReplaceAll]);
  Result := StringReplace(Result, ':00', ':', [rfReplaceAll]);
  Result := StringReplace(Result, ':0', ':', [rfReplaceAll]);
end;
{$ELSE}
var
  buffer: array[0..INET6_ADDRSTRLEN-1] of char;
begin
  if inet_ntop(AF_INET6, @Addr[0], @buffer[0], INET6_ADDRSTRLEN) <> nil then
    Result := string(buffer)
  else
    Result := '';
end;
{$ENDIF}

{$IFDEF DARWIN}
function GetMACAddress(const Ifa: PIfAddrs): string;
var
  sa: Psockaddr_dl;
  i: Integer;
begin
  Result := '';
  if not Assigned(ifa^.ifa_addr) or (ifa^.ifa_addr^.sa_family <> AF_LINK) then
    Exit;

  sa := Psockaddr_dl(ifa^.ifa_addr);
  if sa^.sdl_alen = 0 then
    Exit;

  for i := 0 to sa^.sdl_alen - 1 do
  begin
    if i > 0 then Result := Result + ':';
    Result := Result + LowerCase(IntToHex(Byte(sa^.sdl_data[sa^.sdl_nlen + i]), 2));
  end;
end;
{$ELSE}
function ReadMACAddress(const InterfaceName: string): string;
var
  F: TextFile;
  MACStr: string;
  FileName: string;
begin
  Result := '';
  FileName := '/sys/class/net/' + InterfaceName + '/address';

  if not FileExists(FileName) then
    Exit;

  try
    AssignFile(F, FileName);
    Reset(F);
    try
      ReadLn(F, MACStr);
      Result := Trim(LowerCase(MACStr));
    finally
      CloseFile(F);
    end;
  except
    Result := '';
  end;
end;
{$ENDIF}

function GetBlackBerryInterfaces: TBBInterfaceList;
var
  ifap, ifa: PIfAddrs;
  InterfaceName, MAC, IPv4Addr, IPv4Mask, IPv6Addr: string;
  sin: Psockaddr_in;
  sin6: Psockaddr_in6;
begin
  SetLength(Result, 0);

  if getifaddrs(ifap) <> 0 then
    Exit;

  try
    ifa := ifap;
    while ifa <> nil do
    begin
      try
        // Only process UP interfaces
        if ((ifa^.ifa_flags and IFF_UP) <> 0) and Assigned(ifa^.ifa_name) then
        begin
          InterfaceName := string(ifa^.ifa_name);

          {$IFDEF DARWIN}
          MAC := GetMACAddress(ifa);
          {$ELSE}
          MAC := ReadMACAddress(InterfaceName);
          {$ENDIF}

          IPv4Addr := '';
          IPv4Mask := '';
          IPv6Addr := '';

          if Assigned(ifa^.ifa_addr) then
          begin
            case ifa^.ifa_addr^.sa_family of
              AF_INET:
                begin
                  sin := Psockaddr_in(ifa^.ifa_addr);
                  IPv4Addr := NetAddrToStr(sin^.sin_addr);

                  if Assigned(ifa^.ifa_netmask) then
                  begin
                    sin := Psockaddr_in(ifa^.ifa_netmask);
                    IPv4Mask := NetAddrToStr(sin^.sin_addr);
                  end;
                end;

              AF_INET6:
                begin
                  sin6 := Psockaddr_in6(ifa^.ifa_addr);
                  IPv6Addr := IPv6AddrToStr(sin6^.sin6_addr);
                end;
            end;
          end;

          ProcessInterface(Result, InterfaceName, MAC, IPv4Addr, IPv4Mask, IPv6Addr);
        end;
      except
        // Skip problematic interfaces
      end;

      ifa := ifa^.ifa_next;
    end;
  finally
    freeifaddrs(ifap);
  end;
end;

{$ENDIF}

{$IFDEF WINDOWS}
const
  INET_ADDRSTRLEN = 16;
  INET6_ADDRSTRLEN = 46;

function MACToString(Addr: PByte; Len: ULONG): string;
var
  i: Integer;
begin
  Result := '';
  if (Addr = nil) or (Len = 0) then Exit;

  for i := 0 to Integer(Len) - 1 do
  begin
    if i > 0 then Result := Result + ':';
    Result := Result + LowerCase(IntToHex(Addr^, 2));
    Inc(Addr);
  end;
end;

function GetBlackBerryInterfaces: TBBInterfaceList;
var
  pAdapterAddresses: PIP_ADAPTER_ADDRESSES;
  pCurrentAdapter: PIP_ADAPTER_ADDRESSES;
  pUnicastAddress: PIP_ADAPTER_UNICAST_ADDRESS;
  BufferLength: ULONG;
  RetVal: DWORD;
  xInterface: TBBInterface;
  IPBuffer: array[0..INET6_ADDRSTRLEN-1] of AnsiChar;
  BufferSize: DWORD;
  HasValidAddress: Boolean;
  IPv4Addr, IPv6Addr: string;
begin
  SetLength(Result, 0);

  // Initial buffer size
  BufferLength := 15000;
  GetMem(pAdapterAddresses, BufferLength);

  try
    RetVal := GetAdaptersAddresses(
      AF_UNSPEC,
      GAA_FLAG_INCLUDE_PREFIX or GAA_FLAG_SKIP_ANYCAST or GAA_FLAG_SKIP_MULTICAST,
      nil,
      pAdapterAddresses,
      @BufferLength
    );

    // Retry with larger buffer if needed
    if RetVal = ERROR_BUFFER_OVERFLOW then
    begin
      FreeMem(pAdapterAddresses);
      GetMem(pAdapterAddresses, BufferLength);
      RetVal := GetAdaptersAddresses(
        AF_UNSPEC,
        GAA_FLAG_INCLUDE_PREFIX or GAA_FLAG_SKIP_ANYCAST or GAA_FLAG_SKIP_MULTICAST,
        nil,
        pAdapterAddresses,
        @BufferLength
      );
    end;

    if RetVal <> NO_ERROR then
      Exit;

    pCurrentAdapter := pAdapterAddresses;
    while pCurrentAdapter <> nil do
    begin
      try
        // Only process operational interfaces
        if pCurrentAdapter^.OperStatus = IfOperStatusUp then
        begin
          // Initialize interface record
          xInterface.Name := UTF8Encode(WideCharToString(pCurrentAdapter^.FriendlyName));
          xInterface.MAC := '';
          xInterface.IPv4 := '';
          xInterface.IPv4Phone := '';
          xInterface.IPv6 := '';
          xInterface.IPv6Phone := '';
          HasValidAddress := False;
          IPv4Addr := '';
          IPv6Addr := '';

          // Get MAC address
          if pCurrentAdapter^.PhysicalAddressLength > 0 then
            xInterface.MAC := MACToString(@pCurrentAdapter^.PhysicalAddress[0],
                                       pCurrentAdapter^.PhysicalAddressLength);

          // Process unicast addresses
          pUnicastAddress := pCurrentAdapter^.FirstUnicastAddress;
          while pUnicastAddress <> nil do
          begin
            BufferSize := INET6_ADDRSTRLEN;
            if WSAAddressToStringA(
              pUnicastAddress^.Address.lpSockaddr,
              pUnicastAddress^.Address.iSockaddrLength,
              nil,
              @IPBuffer[0],
              BufferSize
            ) = 0 then
            begin
              case pUnicastAddress^.Address.lpSockaddr^.sa_family of
                AF_INET:
                  begin
                    IPv4Addr := string(IPBuffer);
                    if IsAPIPAAddress(IPv4Addr) then
                      HasValidAddress := True;
                  end;

                AF_INET6:
                  begin
                    IPv6Addr := string(IPBuffer);
                    if IsLinkLocalIPv6(IPv6Addr) then
                      HasValidAddress := True;
                  end;
              end;
            end;
            pUnicastAddress := pUnicastAddress^.Next;
          end;

          // Process interface if it has valid addresses and MAC
          if HasValidAddress and (xInterface.MAC <> '') then
          begin
            ProcessInterface(Result, xInterface.Name, xInterface.MAC,
                           IPv4Addr, '255.255.255.252', IPv6Addr);
          end;
        end;
      except
        // Skip problematic adapters
      end;

      pCurrentAdapter := pCurrentAdapter^.Next;
    end;
  finally
    FreeMem(pAdapterAddresses);
  end;
end;

{$ENDIF}

end.
