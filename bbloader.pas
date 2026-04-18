unit bbLoader;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, bbusb;

const
  MAX_FLASH_BLOCK = $3FF4;

type
  TBBLoader = class
  private
    fUSB: TBBUSB;
  public
    constructor Create(usb: TBBUSB);
    function BugdispLog: TBytes;
    function FlashRegionsInfo: TBytes;
    function BlockedOS: TBytes;
    function BlockedRadio: TBytes;
    function PIN: Dword;
    function BSN: Dword;
    function VendorID: word;
    function HWID_OVERRIDE: TBytes;
    function DRAMInfo: TBytes;
    function SendBlock(var Data: TBytes): boolean;
    function Complete(): boolean;
    function GRS_Wipe(): boolean;
    function PreFlash(x: byte): TBytes;
    function PersistentData: TBytes;
    function GetMCT: TBytes;
    function OSMetrics: TBytes;
    function GetBLog: TBytes;
    function GetLAL: TBytes;
    function GetOSBoot: TBytes;

    procedure EnableLED;
    procedure RemoveInstaller;
    procedure EraseMCT;

    function SendSignature(var Data: TBytes): boolean;
    function Reboot(): boolean;
  end;


implementation

uses
  CLI.Interfaces,    // Core interfaces
  CLI.Command,       // Base command implementation
  CLI.Progress,      // Optional: Progress indicators
  CLI.Console;       // Optional: Colored console output

(*
Command codes documentation:
20 - Retrieving persistent data struct
21 - Retrieving Bootrom Log
39 - (Reserved)
3A - (Reserved)
50 - Get TZ & etc info
AB - Getting the JDM BSN
AC - (Reserved)
AD - Retrieving PMIC Info
AE - Erase blocked FW versions lists
AF - Write DWORD to 8023977c
B0 - Bugdisp log
B1 - Retrieving Flash IDs
B2 - Retrieving DSP OS Metrics
B3 - Retrieving Loader Action Log
B4 - Retrieving Flash Regions Info
B5 - Retrieving Flash Info
B6 - USBMS
B7 - HASH_BOOTROM
BD - Retrieving Hardware Override ID
BE - Setting Hardware Override ID
BF - Retrieving DRAM Info
C0 40 - Requesting COMPLETE
C2 - (Reserved)
C3 - Enable bootrom led
C4 - READVERIFY   00 dword(addr) dword(size) byte(val)
C6 - FACTORY_WIPE (BBOS)
C8 - GRS_WIPE (BBOS)
C9 - USB Test
CB - Retrieving OS boot error info
CC - (Reserved)
CD - (Reserved)
D0 - (Reserved)
D1 - Retrieving SVN
D2 - Retrieving Kernel Metrics
D3 - Retrieving App Metrics
D4 - Appstore NUKE
D5 - SUPER_NUKE
D7 - SetActiveMCT
D8 - OS metrics
D9 - Retrieving MCT
DA - HIS
DB - Retrieving Vendor ID
DC - DO_CRC_VERIFY
DD - FLASH_DUMP
DE - BOOT_MODE
E0 - REMOVE_INSTALLER
E1 - Retrieving Installer Metrics
E3 - ADD_OS_EXTENDED
E4 - CREAD INIT
E5 - CREAD 00 dword(addr?) dword (size<=0x3FA0)
E6 - (Reserved)
E7 - Getting the Device PIN
E8 - WIPE_SECURITY
E9 - Retrieving boot count info
EA - Getting the Device BSN
EB - (Reserved)
EC - Retrieving Blocked OS CFP
ED - Retrieving Blocked Radio OS CFP
EE - ERASE_SECTOR
EE 20 - (Reserved)
EF 80 - Reboot
F1 - Upgrading MCT to resizable partitions
F2 - Resizing MCT partition
F3 - ERASE_ALL_MCT
F4 - Retrieving the Number of UMPs
F5 - Retrieving UMP Information
F6 - Downgrading a resizable MCT to dynamic
F7 - Write data
F8 - Write data
F9 40 - SIGNATURE_TRAILER
FD - (Reserved)
FF - Retrieving DDR Info
*)

  { TBBLoader }

constructor TBBLoader.Create(usb: TBBUSB);
begin
  inherited Create;
  fUSB := usb;
end;

function TBBLoader.BugdispLog: TBytes;
var
  Cmd: word;
  o, l: integer;
  Data: TBytes;
begin
  SetLength(Result, 0);
  o := 0;
  repeat
  try
    Data := fUSB.Channel2($B0, Cmd, [00, 00, 00, 00, 00, 00, 00, 00]);
    l := Length(Data);
    if (Cmd = $B5) and (l > 0) then
    begin
      SetLength(Result, l + o);
      Move(Data[0], Result[o], l);
      Inc(o, l);
    end;
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in BugdispLog: ' + E.Message, ccYellow);
      Break;
    end;
  end;
  until Cmd = $D0;
end;

function TBBLoader.PreFlash(x: byte): TBytes;
var
  Cmd: word;
  Data: TBytes;
begin
  SetLength(Data, 36);
  FillChar(Data[0], Length(Data), 0);
  Data[0] := x;
  Data[1] := $28;
  Data[6] := $02;
  Data[28] := $01;
  Data[32] := $02;

  try
    Result := fUSB.Channel2($20EE, Cmd, Data);
    if Cmd <> $39 then
      SetLength(Result, 0);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in PreFlash: ' + E.Message, ccRed);
      SetLength(Result, 0);
    end;
  end;
end;

function TBBLoader.PersistentData: TBytes;
var
  Cmd: word;
  Data: TBytes;
begin
  SetLength(Data, 1024);
  FillChar(Data[0], Length(Data), 0);
  PDword(@Data[4])^ := $3c6806c;
  PDword(@Data[8])^ := $36159469;
  PDword(@Data[84])^ := $240a2dff;

  try
    Result := fUSB.Channel2($20, Cmd, Data);
    if Cmd <> $39 then
      SetLength(Result, 0);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in PersistentData: ' + E.Message, ccRed);
      SetLength(Result, 0);
    end;
  end;
end;

function TBBLoader.GetBLog: TBytes;
var
  Cmd: word;
begin
  try
    Result := fUSB.Channel2($21, Cmd, []);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in GetBlog: ' + E.Message, ccRed);
      SetLength(Result, 0);
    end;
  end;
end;

function TBBLoader.GetOSBoot: TBytes;
var
  Cmd: word;
begin
  try
    Result := fUSB.Channel2($CB, Cmd, []);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in GetLAL: ' + E.Message, ccRed);
      SetLength(Result, 0);
    end;
  end;
end;

function TBBLoader.GetLAL: TBytes;
var
  Cmd: word;
begin
  try
    Result := fUSB.Channel2($B3, Cmd, [0, 0, 0, 0]);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in GetLAL: ' + E.Message, ccRed);
      SetLength(Result, 0);
    end;
  end;
end;

function TBBLoader.GetMCT: TBytes;
var
  Cmd: word;
begin
  try
    Result := fUSB.Channel2($D9, Cmd, []);
    if Cmd <> $C9 then
      SetLength(Result, 0);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in GetMCT: ' + E.Message, ccRed);
      SetLength(Result, 0);
    end;
  end;
end;


function TBBLoader.FlashRegionsInfo: TBytes;
var
  Cmd: word;
begin
  try
    Result := fUSB.Channel2($B4, Cmd, []);
    if Cmd <> $D2 then
      SetLength(Result, 0);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in FlashRegionsInfo: ' + E.Message, ccRed);
      SetLength(Result, 0);
    end;
  end;
end;

function TBBLoader.PIN: Dword;
var
  Cmd: word;
  Buff: TBytes;
begin
  Result := 0;
  try
    Buff := fUSB.Channel2($E7, Cmd, []);
    if (Cmd = $D1) and (Length(Buff) >= SizeOf(DWord)) then
      Result := PDword(@Buff[0])^;
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in PIN: ' + E.Message, ccRed);
      Result := 0;
    end;
  end;
end;

function TBBLoader.BSN: Dword;
var
  Cmd: word;
  Buff: TBytes;
begin
  Result := 0;
  try
    Buff := fUSB.Channel2($EA, Cmd, []);
    if (Cmd = $FC) and (Length(Buff) >= SizeOf(DWord)) then
      Result := PDword(@Buff[0])^;
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in BSN: ' + E.Message, ccRed);
      Result := 0;
    end;
  end;
end;

function TBBLoader.VendorID: word;
var
  Cmd: word;
  Buff: TBytes;
begin
  Result := 0;
  try
    Buff := fUSB.Channel2($DB, Cmd, []);
    if (Cmd = $CB) and (Length(Buff) >= SizeOf(DWord)) then
      Result := Pword(@Buff[2])^;
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in VendorID: ' + E.Message, ccRed);
      Result := 0;
    end;
  end;
end;

function TBBLoader.HWID_OVERRIDE: TBytes;
var
  Cmd: word;
begin
  try
    Result := fUSB.Channel2($BD, Cmd, []);
    if (Cmd <> $BE) then
      SetLength(Result, 0);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in HWID_OVERRIDE: ' + E.Message, ccRed);
      SetLength(Result, 0);
    end;
  end;
end;


function TBBLoader.SendBlock(var Data: TBytes): boolean;
var
  Cmd: word;
begin
  Result := False;
  try
    fUSB.Channel2($F7, Cmd, Data);
    Result := (Cmd = $DF);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in SendBlock: ' + E.Message, ccRed);
    end;
  end;
end;

function TBBLoader.SendSignature(var Data: TBytes): boolean;
var
  Cmd: word;
begin
  Result := False;
  try
    fUSB.Channel2($40F9, Cmd, Data);
    Result := (Cmd = $4006);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in SendSignature: ' + E.Message, ccRed);
    end;
  end;
end;

function TBBLoader.Complete(): boolean;
var
  Cmd: word;
begin
  Result := False;
  try
    fUSB.Channel2($40C0, Cmd, []);
    Result := (Cmd = $4006);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in Complete: ' + E.Message, ccRed);
    end;
  end;
end;

function TBBLoader.GRS_Wipe(): boolean;
var
  Cmd: word;
  Buff: TBytes;
begin
  Result := False;
  try
    SetLength(Buff, MAX_FLASH_BLOCK);
    fUSB.Channel2($C8, Cmd, Buff);
    Result := (Cmd = $D8);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in GRS_Wipe: ' + E.Message, ccRed);
    end;
  end;
end;

function TBBLoader.Reboot(): boolean;
var
  Cmd: word;
begin
  Result := False;
  try
    fUSB.Channel2($80EF, Cmd, []);
    Result := (Cmd = $80C7);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in Reboot: ' + E.Message, ccRed);
    end;
  end;
end;

function TBBLoader.BlockedOS: TBytes;
var
  Cmd: word;
begin
  try
    Result := fUSB.Channel2($EC, Cmd, []);
    if Cmd <> $FD then
      SetLength(Result, 0);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in BlockedOS: ' + E.Message, ccRed);
      SetLength(Result, 0);
    end;
  end;
end;

function TBBLoader.DRAMInfo: TBytes;
var
  Cmd: word;
begin
  try
    Result := fUSB.Channel2($BF, Cmd, []);
    if Cmd <> $D9 then
      SetLength(Result, 0);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in DRAMInfo: ' + E.Message, ccRed);
      SetLength(Result, 0);
    end;
  end;
end;

procedure TBBLoader.EnableLED;
var
  Cmd: word;
begin
  try
    fUSB.Channel2($C3, Cmd, []);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in EnableLED: ' + E.Message, ccRed);
    end;
  end;
end;

procedure TBBLoader.RemoveInstaller;
var
  Cmd: word;
begin
  try
    fUSB.Channel2($E0, Cmd, []);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in RemoveInstaller: ' + E.Message, ccRed);
    end;
  end;
end;

procedure TBBLoader.EraseMCT;
var
  Cmd: word;
begin
  try
    fUSB.Channel2($F3, Cmd, []);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in EraseMCT: ' + E.Message, ccRed);
    end;
  end;
end;

function TBBLoader.BlockedRadio: TBytes;
var
  Cmd: word;
begin
  try
    Result := fUSB.Channel2($ED, Cmd, []);
    if Cmd <> $FE then
      SetLength(Result, 0);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in BlockedRadio: ' + E.Message, ccRed);
      SetLength(Result, 0);
    end;
  end;
end;

function TBBLoader.OSMetrics: TBytes;
var
  Cmd: word;
begin
  try
    Result := fUSB.Channel2($D8, Cmd, []);
    if Cmd <> $C8 then
      SetLength(Result, 0);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error in OSMetrics: ' + E.Message, ccRed);
      SetLength(Result, 0);
    end;
  end;
end;

end.
