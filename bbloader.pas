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
    function SafeChannel2(Cmd: word; const Data: TBytes; expectedResp: word; const FuncName: string): TBytes;
    function SafeChannel2Bool(Cmd: word; const Data: TBytes; expectedResp: word;
      const FuncName: string): boolean;
  public
    constructor Create(usb: TBBUSB);
    function BugdispLog: TBytes;
    function FlashRegionsInfo: TBytes;
    function BlockedOS: TBytes;
    function BlockedRadio: TBytes;
    function PIN: DWord;
    function BSN: DWord;
    function VendorID: word;
    function HWID_OVERRIDE: TBytes;
    function DRAMInfo: TBytes;
    function SendBlock(const Data: TBytes): boolean;
    function Complete: boolean;
    function GRS_Wipe: boolean;
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

    function SendSignature(const Data: TBytes): boolean;
    function Reboot: boolean;
  end;

implementation

uses
  CLI.Console;

  { TBBLoader }

constructor TBBLoader.Create(usb: TBBUSB);
begin
  inherited Create;
  fUSB := usb;
end;

// Допоміжний метод для безпечного зчитування масивів байтів
function TBBLoader.SafeChannel2(Cmd: word; const Data: TBytes; expectedResp: word;
  const FuncName: string): TBytes;
var
  RespCmd: word;
begin
  try
    Result := fUSB.Channel2(Cmd, RespCmd, Data);
    if (expectedResp <> $0000) and (RespCmd <> expectedResp) then
      SetLength(Result, 0);
  except
    on E: Exception do
    begin
      TConsole.WriteLn(Format('Error in %s: %s', [FuncName, E.Message]), ccRed);
      SetLength(Result, 0);
    end;
  end;
end;

// Допоміжний метод для перевірки виконання команд (повертає boolean)
function TBBLoader.SafeChannel2Bool(Cmd: word; const Data: TBytes; expectedResp: word;
  const FuncName: string): boolean;
var
  RespCmd: word;
begin
  Result := False;
  try
    fUSB.Channel2(Cmd, RespCmd, Data);
    Result := (RespCmd = expectedResp);
  except
    on E: Exception do
    begin
      TConsole.WriteLn(Format('Error in %s: %s', [FuncName, E.Message]), ccRed);
    end;
  end;
end;

function TBBLoader.BugdispLog: TBytes;
var
  Cmd: word;
  o, l: integer;
  Data: TBytes;
  Dummy: TBytes;
begin
  SetLength(Result, 0);
  SetLength(Dummy, 8);
  FillChar(Dummy[0], 8, 0);
  o := 0;
  repeat
  try
    Data := fUSB.Channel2($B0, Cmd, Dummy);
    l := Length(Data);
    if (Cmd = $B5) and (l > 0) then
    begin
      SetLength(Result, o + l);
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
  Data: TBytes;
begin
  SetLength(Data, 36);
  FillChar(Data[0], Length(Data), 0);
  Data[0] := x;
  Data[1] := $28;
  Data[6] := $02;
  Data[28] := $01;
  Data[32] := $02;

  Result := SafeChannel2($20EE, Data, $39, 'PreFlash');
end;

function TBBLoader.PersistentData: TBytes;
var
  Data: TBytes;
begin
  SetLength(Data, 1024);
  FillChar(Data[0], Length(Data), 0);
  PDWord(@Data[4])^ := $03C6806C;
  PDWord(@Data[8])^ := $36159469;
  PDWord(@Data[84])^ := $240A2DFF;

  Result := SafeChannel2($20, Data, $39, 'PersistentData');
end;

function TBBLoader.GetBLog: TBytes;
begin
  Result := SafeChannel2($21, [], $0000, 'GetBLog');
end;

function TBBLoader.GetOSBoot: TBytes;
begin
  Result := SafeChannel2($CB, [], $0000, 'GetOSBoot');
end;

function TBBLoader.GetLAL: TBytes;
begin
  Result := SafeChannel2($B3, [0, 0, 0, 0], $0000, 'GetLAL');
end;

function TBBLoader.GetMCT: TBytes;
begin
  Result := SafeChannel2($D9, [], $C9, 'GetMCT');
end;

function TBBLoader.FlashRegionsInfo: TBytes;
begin
  Result := SafeChannel2($B4, [], $D2, 'FlashRegionsInfo');
end;

function TBBLoader.PIN: DWord;
var
  Cmd: word;
  Buff: TBytes;
begin
  Result := 0;
  try
    Buff := fUSB.Channel2($E7, Cmd, []);
    if (Cmd = $D1) and (Length(Buff) >= SizeOf(DWord)) then
      Result := PDWord(@Buff[0])^;
  except
    on E: Exception do
      TConsole.WriteLn('Error in PIN: ' + E.Message, ccRed);
  end;
end;

function TBBLoader.BSN: DWord;
var
  Cmd: word;
  Buff: TBytes;
begin
  Result := 0;
  try
    Buff := fUSB.Channel2($EA, Cmd, []);
    if (Cmd = $FC) and (Length(Buff) >= SizeOf(DWord)) then
      Result := PDWord(@Buff[0])^;
  except
    on E: Exception do
      TConsole.WriteLn('Error in BSN: ' + E.Message, ccRed);
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
    if (Cmd = $CB) and (Length(Buff) >= 4) then
      Result := PWord(@Buff[2])^;
  except
    on E: Exception do
      TConsole.WriteLn('Error in VendorID: ' + E.Message, ccRed);
  end;
end;

function TBBLoader.HWID_OVERRIDE: TBytes;
begin
  Result := SafeChannel2($BD, [], $BE, 'HWID_OVERRIDE');
end;

function TBBLoader.SendBlock(const Data: TBytes): boolean;
begin
  Result := SafeChannel2Bool($F7, Data, $DF, 'SendBlock');
end;

function TBBLoader.SendSignature(const Data: TBytes): boolean;
begin
  Result := SafeChannel2Bool($40F9, Data, $4006, 'SendSignature');
end;

function TBBLoader.Complete: boolean;
var
  RespCmd: word;
begin
  Result := False;
  try
    fUSB.Channel2($40C0, RespCmd, []);
    Result := (RespCmd = $4006) or (RespCmd = $402E);
    if not Result then
      TConsole.WriteLn(Format('Complete returned unexpected response 0x%.4X',
        [RespCmd]), ccRed);
  except
    on E: Exception do
      TConsole.WriteLn('Error in Complete: ' + E.Message, ccRed);
  end;
end;

function TBBLoader.GRS_Wipe: boolean;
var
  Buff: TBytes;
begin
  SetLength(Buff, MAX_FLASH_BLOCK);
  FillChar(Buff[0], MAX_FLASH_BLOCK, 0);
  Result := SafeChannel2Bool($C8, Buff, $D8, 'GRS_Wipe');
end;

function TBBLoader.Reboot: boolean;
begin
  Result := SafeChannel2Bool($80EF, [], $80C7, 'Reboot');
end;

function TBBLoader.BlockedOS: TBytes;
begin
  Result := SafeChannel2($EC, [], $FD, 'BlockedOS');
end;

function TBBLoader.DRAMInfo: TBytes;
begin
  Result := SafeChannel2($BF, [], $D9, 'DRAMInfo');
end;

procedure TBBLoader.EnableLED;
begin
  SafeChannel2Bool($C3, [], $0000, 'EnableLED');
end;

procedure TBBLoader.RemoveInstaller;
begin
  SafeChannel2Bool($E0, [], $0000, 'RemoveInstaller');
end;

procedure TBBLoader.EraseMCT;
begin
  SafeChannel2Bool($F3, [], $0000, 'EraseMCT');
end;

function TBBLoader.BlockedRadio: TBytes;
begin
  Result := SafeChannel2($ED, [], $FE, 'BlockedRadio');
end;

function TBBLoader.OSMetrics: TBytes;
begin
  Result := SafeChannel2($D8, [], $C8, 'OSMetrics');
end;

end.
