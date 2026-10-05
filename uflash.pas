unit uFlash;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  RamLoader,
  uInfo,
  CLI.Interfaces,    // Core interfaces
  CLI.Command,       // Base command implementation
  CLI.Parameter,     // Parameter handling
  CLI.Progress,      // Progress indicators
  CLI.Console;       // Colored console output

type
  TFlashCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

  TLoaderCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

  TNukeCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

  TInfoCommand = class(TBaseCommand)
  private
    function ConnectToBootROM(RAM: TRamLoader; delay: integer): boolean;
    procedure DisplayDeviceInfo(RAM: TRamLoader);
    procedure DisplayBootROMInfo(RAM: TRamLoader);
    procedure DisplaySecurityInfo(BRMetrics: PBRMetrics);
    procedure DisplayHardwareInfo(BRMetrics: PBRMetrics);
    procedure DisplayOSBlockingInfo(BRMetrics: PBRMetrics);
    procedure DisplayHWVInfo(BRMetrics: PBRMetrics);
    procedure ProcessMCTData(RAM: TRamLoader; Stream: TMemoryStream);
    function FindMCTSignature(const Data: TBytes): integer;
    procedure DisplayFlashInfo(RAM: TRamLoader);
    procedure DisplayDRAMInfo(RAM: TRamLoader);
    procedure DisplayBrandingAndOSInfo(RAM: TRamLoader);
    procedure DisplayBlocklist(const Title: string; const Data: TBytes);
  public
    function Execute: integer; override;
  end;

var
  Flash: TFlashCommand;
  Loader: TLoaderCommand;
  Info: TInfoCommand;
  Nuke: TNukeCommand;

implementation

uses
  MCT,
  FileUtil,
  StrUtils,
  uMisc;

const
  MAX_CONNECTION_ATTEMPTS = 50;
  DEFAULT_LOADER_DELAY = 1000;
  MCT_SIGNATURE = $92be564a;

function TLoaderCommand.Execute: integer;
var
  RAM: TRamLoader;
begin
  RAM := TRamLoader.Create();
  try
    RAM.ProbeLoaders;
    Result := 0;
  finally
    FreeAndNil(RAM);
  end;
end;

function IsValidUTF8Sequence(const Buffer: array of byte; StartPos: integer;
  out SeqLength: integer): boolean;
var
  B: byte;
  I, ExpectedBytes: integer;
begin
  Result := False;
  SeqLength := 1;

  if StartPos >= Length(Buffer) then
    Exit;

  B := Buffer[StartPos];

  // ASCII (0xxxxxxx)
  if B <= $7F then
  begin
    Result := True;
    Exit;
  end;

  if (B and $E0) = $C0 then
    ExpectedBytes := 2
  else if (B and $F0) = $E0 then
    ExpectedBytes := 3
  else if (B and $F8) = $F0 then
    ExpectedBytes := 4
  else
    Exit;

  if StartPos + ExpectedBytes > Length(Buffer) then
    Exit;

  SeqLength := ExpectedBytes;

  for I := 1 to ExpectedBytes - 1 do
  begin
    if (Buffer[StartPos + I] and $C0) <> $80 then
      Exit;
  end;

  case ExpectedBytes of
    2: Result := (B >= $C2);
    3: Result := not ((B = $E0) and ((Buffer[StartPos + 1] and $E0) = $80));
    4: Result := not ((B = $F0) and ((Buffer[StartPos + 1] and $F0) = $80));
  end;
end;

function IsValidTextContent(const Buffer: array of byte; Size: integer): boolean;
var
  I, SeqLength: integer;
  ValidUTF8Count, TotalMultiByteCount: integer;
begin
  Result := False;
  I := 0;
  ValidUTF8Count := 0;
  TotalMultiByteCount := 0;

  while I < Size do
  begin
    if Buffer[I] = 0 then
      Exit;

    if (Buffer[I] < 32) and not (Buffer[I] in [9, 10, 13]) then
      Exit;

    if Buffer[I] > $7F then
    begin
      Inc(TotalMultiByteCount);
      if IsValidUTF8Sequence(Buffer, I, SeqLength) then
      begin
        Inc(ValidUTF8Count);
        Inc(I, SeqLength);
      end
      else
      begin
        if (TotalMultiByteCount > 10) and ((ValidUTF8Count * 100) div TotalMultiByteCount < 80) then
          Exit;
        Inc(I);
      end;
    end
    else
      Inc(I);
  end;

  Result := True;
end;

function IsTextFile(const FileName: string): boolean;
const
  MaxCheckSize = 4096;
  UTF8_BOM: array[0..2] of byte = ($EF, $BB, $BF);
  UTF16LE_BOM: array[0..1] of byte = ($FF, $FE);
  UTF16BE_BOM: array[0..1] of byte = ($FE, $FF);
var
  Stream: TFileStream;
  Buffer: array[0..MaxCheckSize - 1] of byte;
  BytesRead: integer;
  BOM: array[0..2] of byte;
begin
  Result := False;

  if not FileExists(FileName) then
    Exit;

  try
    Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
    try
      if Stream.Size = 0 then
        Exit(True);

      FillChar(BOM, SizeOf(BOM), 0);
      BytesRead := Stream.Read(BOM, SizeOf(BOM));

      if (BytesRead >= 3) and CompareMem(@BOM, @UTF8_BOM, 3) then
        Exit(True);

      if (BytesRead >= 2) and CompareMem(@BOM, @UTF16LE_BOM, 2) then
        Exit(True);

      if (BytesRead >= 2) and CompareMem(@BOM, @UTF16BE_BOM, 2) then
        Exit(True);

      Stream.Position := 0;
      BytesRead := Stream.Read(Buffer, SizeOf(Buffer));

      if not IsValidTextContent(Buffer, BytesRead) then
        Exit(False);

      Result := True;
    finally
      Stream.Free;
    end;
  except
    Result := False;
  end;
end;

function TFlashCommand.Execute: integer;
var
  FL: TStringList;
  TmpArray: array of string;
  InputParam, ListParam, DelayParam, VersParam, LoadersParam: string;
  I, K, Ver, RunLoaderDelay, Attempts: integer;
  VersList: TStringList;
  Spinner: IProgressIndicator;
  RAM: TRamLoader;
  FileName, DisplayName: string;
begin
  Result := 0;
  Ver := 2;
  RAM := nil;

  GetParameterValue('--input', InputParam);
  GetParameterValue('--list', ListParam);
  GetParameterValue('--versions', VersParam);
  GetParameterValue('--loaders', LoadersParam);

  if GetParameterValue('--delay', DelayParam) then
    RunLoaderDelay := StrToIntDef(DelayParam, DEFAULT_LOADER_DELAY)
  else
    RunLoaderDelay := DEFAULT_LOADER_DELAY;

  if (VersParam <> '') then
  begin
    Ver := 0;
    VersList := TStringList.Create;
    try
      VersList.AddCommaText(VersParam);
      VersList.Sorted := True;
      if VersList.IndexOf('1') >= 0 then Inc(Ver, 1);
      if VersList.IndexOf('2') >= 0 then Inc(Ver, 2);
    finally
      FreeAndNil(VersList);
    end;
  end;

  if not (Ver in [1, 2, 3]) then
    Ver := 3;

  FL := TStringList.Create;
  try
    if (ListParam <> '') then
    begin
      ListParam := ExpandFileName(ListParam);
      if FileExists(ListParam) and IsTextFile(ListParam) and (FileSize(ListParam) < 8192) then
        FL.LoadFromFile(ListParam)
      else if FileExists(ListParam) then
        TConsole.WriteLn('Warning: list file looks like binary or too big (more than 8k). Skipping',
          ccYellow);
    end;

    if InputParam <> '' then
      FL.AddCommaText(InputParam);

    for I := FL.Count - 1 downto 0 do
    begin
      TmpArray := SplitString(FL[I], '=');
      FileName := ExpandFileName(TmpArray[0]);

      if not FileExists(FileName) then
      begin
        TConsole.WriteLn('Warning: File not found - ' + FileName, ccYellow);
        FL.Delete(I);
      end
      else
        FL.Strings[I] := FileName;
    end;

    if FL.Count = 0 then
    begin
      TConsole.WriteLn('Error: no valid files found', ccRed);
      Exit(10);
    end;

    TConsole.WriteLn('Connecting to BootROM...');

    Spinner := CreateSpinner(ssDots);
    RAM := TRamLoader.Create(LoadersParam);
    try
      Attempts := 0;
      Spinner.Start;

      while Attempts < MAX_CONNECTION_ATTEMPTS do
      begin
        try
          if RAM.ConnectToBB(RunLoaderDelay, True) then
            Break;
        except
          on E: Exception do
          begin
            Spinner.Stop;
            TConsole.WriteLn('Connection error: ' + E.Message, ccRed);
            Inc(Attempts);
            if Attempts >= MAX_CONNECTION_ATTEMPTS then
            begin
              TConsole.WriteLn('Too many connection attempts', ccRed);
              Exit(11);
            end;
            Sleep(100);
            Spinner.Start;
          end;
        end;
        Inc(Attempts);
      end;

      Spinner.Stop;

      if Attempts >= MAX_CONNECTION_ATTEMPTS then
      begin
        TConsole.WriteLn('Failed to connect after maximum attempts', ccRed);
        Exit(11);
      end;

      TConsole.WriteLn('Flashing ' + IntToStr(FL.Count) + ' files...');
      for I := 0 to FL.Count - 1 do
      begin
        DisplayName := ExtractFileName(FL[I]);
        if DisplayName.EndsWith('!') then
          DisplayName := DisplayName.TrimRight(['!']);

        TConsole.WriteLn('Flashing: ' + DisplayName);
        K := RAM.FlashFile(FL[I], Ver);
        if K < 0 then
        begin
          TConsole.WriteLn('Error flashing file: ' + DisplayName, ccRed);
          if K = -3 then Break;
        end;
      end;

      TConsole.WriteLn('Rebooting phone...');
      RAM.RebootPhone;
      TConsole.WriteLn('Flash completed successfully!', ccGreen);

    finally
      FreeAndNil(RAM);
    end;

  finally
    FreeAndNil(FL);
  end;
end;

function TInfoCommand.Execute: integer;
var
  RAM: TRamLoader;
  DelayParam, LoadersParam: string;
  RunLoaderDelay: integer;
  Stream: TMemoryStream;
begin
  Result := 0;
  RAM := nil;
  Stream := nil;

  try
    GetParameterValue('--loaders', LoadersParam);
    GetParameterValue('--delay', DelayParam);

    RunLoaderDelay := StrToIntDef(DelayParam, DEFAULT_LOADER_DELAY);
    RAM := TRamLoader.Create(LoadersParam);

    if not ConnectToBootROM(RAM, RunLoaderDelay) then
      Exit(11);

    DisplayDeviceInfo(RAM);
    DisplayBootROMInfo(RAM);

    Stream := TMemoryStream.Create;
    ProcessMCTData(RAM, Stream);

    DisplayFlashInfo(RAM);
    DisplayDRAMInfo(RAM);
    DisplayBrandingAndOSInfo(RAM);

    TConsole.WriteLn('');
    DisplayBlocklist('OS Blocklist:', RAM.Loader.BlockedOS);
    DisplayBlocklist('Radio Blocklist:', RAM.Loader.BlockedRadio);

    RAM.RebootPhone;

  finally
    FreeAndNil(Stream);
    FreeAndNil(RAM);
  end;
end;

function TInfoCommand.ConnectToBootROM(RAM: TRamLoader; delay: integer): boolean;
var
  Spinner: IProgressIndicator;
  Attempts: integer;
begin
  Result := False;
  TConsole.WriteLn('Connecting to BootROM...');

  Spinner := CreateSpinner(ssDots);
  Attempts := 0;

  Spinner.Start;
  try
    while Attempts < MAX_CONNECTION_ATTEMPTS do
    begin
      try
        if RAM.ConnectToBB(delay) then
        begin
          Result := True;
          Break;
        end;
      except
        on E: Exception do
        begin
          Spinner.Stop;
          TConsole.WriteLn('Connection error: ' + E.Message, ccRed);
          Inc(Attempts);
          if Attempts >= MAX_CONNECTION_ATTEMPTS then
          begin
            TConsole.WriteLn('Too many connection attempts', ccRed);
            Break;
          end;
          Sleep(100);
          Spinner.Start;
        end;
      end;
      Inc(Attempts);
    end;
  finally
    Spinner.Stop;
  end;

  TConsole.WriteLn('');
end;

procedure TInfoCommand.DisplayDeviceInfo(RAM: TRamLoader);
begin
  TConsole.WriteLn('QNX Device Info:');
  TConsole.WriteLn(Format('  PIN:                %.8X', [cardinal(RAM.Loader.PIN)]));
  TConsole.WriteLn(Format('  BSN:                %d', [uint64(RAM.Loader.BSN)]));
  TConsole.WriteLn('');
end;

procedure TInfoCommand.DisplayBootROMInfo(RAM: TRamLoader);
var
  HWID: THW_Override;
  TmpData: TBytes;
  BRMetrics: PBRMetrics;
begin
  TmpData := RAM.Loader.HWID_OVERRIDE;
  if Length(TmpData) = SizeOf(THW_Override) then
    HWID := PHW_Override(@TmpData[0])^
  else
    FillChar(HWID, SizeOf(HWID), 0);

  if Length(RAM.BootromInfo) < SizeOf(TBRMetrics) + 4 then Exit;

  BRMetrics := PBRMetrics(@RAM.BootromInfo[4]);

  with BRMetrics^ do
  begin
    TConsole.WriteLn(Format('Bootrom Version:   %d.%d.%d.%d',
      [TFourInts(BR_ver)[3], TFourInts(BR_ver)[2], TFourInts(BR_ver)[1], TFourInts(BR_ver)[0]]));
    TConsole.WriteLn(Format('  Hardware ID:        0x%.8X %s',
      [cardinal(RAM.ModelID), ReadCString(HardwareName)]));
    TConsole.WriteLn(Format('  HW ID Override:    0x%.8X (OSTypes: 0x%.8X)',
      [cardinal(HWID.ID), cardinal(HWID.OS)]));
    TConsole.WriteLn(Format('  Hardware OS ID:    0x%.8X', [cardinal(HWOSID)]));
    TConsole.WriteLn(Format('  BR ID:              0x%.8X', [cardinal(BRID)]));
    TConsole.WriteLn(Format('  Metrics Version:   %d.%d', [(version shr 16) and $FF, version and $FF]));
    TConsole.WriteLn(Format('  Build Date:         %s', [ReadCString(BuildDate)]));
    TConsole.WriteLn(Format('  Build Time:         %s', [ReadCString(BuildTime)]));
    TConsole.WriteLn(Format('  Build User:         %s', [ReadCString(BuildUser)]));
  end;

  DisplaySecurityInfo(BRMetrics);
  DisplayHardwareInfo(BRMetrics);
  DisplayOSBlockingInfo(BRMetrics);
  DisplayHWVInfo(BRMetrics);
end;

procedure TInfoCommand.DisplaySecurityInfo(BRMetrics: PBRMetrics);
begin
  with BRMetrics^ do
  begin
    TConsole.WriteLn(Format('  Supported Options: 0x%.8X', [cardinal(SupportedOptions)]));
    TConsole.WriteLn(Format('  Drivers:           0x%.8X', [cardinal(Drivers)]));
    TConsole.WriteLn(Format('  Processor:         0x%.8X', [cardinal(Processor)]));
    TConsole.WriteLn(Format('  FlashID:           0x%.8X', [cardinal(FlashID)]));
    TConsole.WriteLn(Format('  LDR Blocks:        0x%.8X', [cardinal(LDRBlocks)]));
    TConsole.WriteLn(Format('  Bootrom Size:      0x%.8X', [cardinal(BootromSize)]));
    TConsole.WriteLn(Format('  Persist Data Addr: 0x%.8X', [cardinal(PersistAddr)]));
  end;
end;

procedure TInfoCommand.DisplayHardwareInfo(BRMetrics: PBRMetrics);
begin
  if BRMetrics^.HWV_off <> 0 then
    TConsole.WriteLn('  External MCT/HWV:  Enabled')
  else
    TConsole.WriteLn('  External MCT/HWV:  Disabled');
end;

procedure TInfoCommand.DisplayOSBlockingInfo(BRMetrics: PBRMetrics);
begin
  with BRMetrics^ do
  begin
    if (PDword(@OldestMFI)^ = 0) and (PDword(@OldestSFI)^ = 0) then
      TConsole.WriteLn('  OS Blocking by Date:   Disabled')
    else
    begin
      TConsole.WriteLn('  OS Blocking by Date:   Enabled');
      TConsole.WriteLn(Format('    Oldest Allowed MFI:  %d/%d/%d',
        [OldestMFI.Month, OldestMFI.Day, OldestMFI.Year]));
      TConsole.WriteLn(Format('    Oldest Allowed SFI:  %d/%d/%d',
        [OldestSFI.Month, OldestSFI.Day, OldestSFI.Year]));
    end;
  end;
end;

procedure TInfoCommand.DisplayHWVInfo(BRMetrics: PBRMetrics);
var
  I: integer;
begin
  with BRMetrics^ do
  begin
    if HWV_off > 0 then
    begin
      TConsole.WriteLn('');
      TConsole.WriteLn('  HWV:');
      for I := 0 to High(HVW) do
      begin
        if HVW[I].ID = $FF then
          Break;
        TConsole.WriteLn('    ' + HWVtoString(HVW[I]));
      end;
    end;
  end;
end;

procedure TInfoCommand.ProcessMCTData(RAM: TRamLoader; Stream: TMemoryStream);
var
  I, P: integer;
  MCT: TMCTParsed;
  TmpData: TBytes;
begin
  P := FindMCTSignature(RAM.BootromInfo);

  if P > 0 then
  begin
    TConsole.WriteLn('');
    I := Length(RAM.BootromInfo) - P;
    Stream.WriteBuffer(RAM.BootromInfo[P], I);
    Stream.Position := 0;
    MCT := ParseMCTStream(Stream);
    ShowParsedMCT(MCT);
    Stream.Clear;

    TmpData := RAM.Loader.GetMCT;
    if Length(TmpData) > 0 then
    begin
      TConsole.WriteLn('');
      Stream.WriteBuffer(TmpData[0], Length(TmpData));
      Stream.Position := 0;
      MCT := ParseMCTStream(Stream);
      ShowParsedMCT(MCT, True);
    end;
  end;
end;

function TInfoCommand.FindMCTSignature(const Data: TBytes): integer;
var
  I: integer;
begin
  Result := 0;
  I := SizeOf(TBRMetrics) + 4;

  while I <= Length(Data) - 4 do
  begin
    if PDword(@Data[I])^ = MCT_SIGNATURE then
    begin
      Result := I;
      Break;
    end;
    Inc(I, 4);
  end;
end;

procedure TInfoCommand.DisplayFlashInfo(RAM: TRamLoader);
var
  FlashData: TBytes;
begin
  FlashData := RAM.Loader.FlashRegionsInfo;
  if Length(FlashData) >= SizeOf(TFlashInfo) then
  begin
    with PFlashInfo(@FlashData[0])^ do
    begin
      TConsole.WriteLn('');
      TConsole.WriteLn('Flash:');
      TConsole.WriteLn(Format('  Flash ID:              NAND blocks 0-%d', [Blocks]));
      TConsole.WriteLn(Format('  Device ID:             0x%.2X', [DeviceID]));
      TConsole.WriteLn(Format('  Vendor ID:             0x%.2X', [VendorID]));
      TConsole.WriteLn(Format('  Manufacturer Name:     %s', [EMMCVendorByID(VendorID)]));
      TConsole.WriteLn(Format('  Product Name:          %s', [ReadCString(Name)]));
      TConsole.WriteLn(Format('  Product Serial Number: 0x%.8X', [cardinal(Serial)]));
      TConsole.WriteLn('  MMC Partition Info:');
      TConsole.WriteLn(Format('    User:                %d KB', [user]));
    end;
  end;
end;

procedure TInfoCommand.DisplayDRAMInfo(RAM: TRamLoader);
var
  DramData: TBytes;
begin
  DramData := RAM.Loader.DRAMInfo;
  if Length(DramData) >= SizeOf(TDRAM_Info) then
  begin
    with PDRAM_Info(@DramData[0])^ do
    begin
      TConsole.WriteLn('');
      TConsole.WriteLn('DRAM:');
      TConsole.WriteLn(Format('  Size:               %d MB', [Size div (1024 * 1024)]));
      TConsole.WriteLn(Format('  VendorID:           0x%X', [vendor]));
      TConsole.WriteLn(Format('  Vendor Name:        %s', [DRAMVendorByID(vendor)]));
      TConsole.WriteLn(Format('  Revision:           0x%X', [revision]));
    end;
  end;
end;

procedure TInfoCommand.DisplayBrandingAndOSInfo(RAM: TRamLoader);
var
  OsData: TBytes;
begin
  TConsole.WriteLn('');
  TConsole.WriteLn('Branding:');
  TConsole.WriteLn(Format('  ECID:               %d', [cardinal(RAM.Loader.VendorID)]));

  OsData := RAM.Loader.OSMetrics;
  if Length(OsData) >= SizeOf(TOSMetrics) then
  begin
    with POSMetrics(@OsData[0])^ do
    begin
      TConsole.WriteLn('');
      TConsole.WriteLn(Format('OS Version:          %s', [VersionToString(os_version)]));
      TConsole.WriteLn(Format('  Hardware ID:        0x%.8X %s',
        [cardinal(hardware_id), ReadCString(device_string)]));
      TConsole.WriteLn(Format('  Metrics Version:   %d.%d', [version shr 16, version and $FF]));
      TConsole.WriteLn(Format('  Build Date:         %s', [ReadCString(build_date)]));
      TConsole.WriteLn(Format('  Build Time:         %s', [ReadCString(build_time)]));
      TConsole.WriteLn(Format('  Build User:         %s', [ReadCString(build_user)]));
      TConsole.WriteLn(Format('  OS Address:         0x%.8X-0x%.8X',
        [cardinal(load_base_ptr), cardinal(load_end_ptr - 1)]));
    end;
  end;
end;

procedure TInfoCommand.DisplayBlocklist(const Title: string; const Data: TBytes);
var
  SL: TStringList;
  Item: string;
begin
  SL := DecodeBlocked(Data);
  if SL <> nil then
  begin
    try
      TConsole.WriteLn(Title);
      for Item in SL do
        TConsole.WriteLn(Item);
    finally
      FreeAndNil(SL);
    end;
  end;
end;

function TNukeCommand.Execute: integer;
var
  Spinner: IProgressIndicator;
  Attempts: integer;
  RAM: TRamLoader;
begin
  Result := 1;
  TConsole.WriteLn('Connecting to BootROM...');

  Spinner := CreateSpinner(ssDots);
  Attempts := 0;
  RAM := TRamLoader.Create;
  try
    Spinner.Start;
    while Attempts < MAX_CONNECTION_ATTEMPTS do
    begin
      try
        if RAM.ConnectToBB(-1) then
        begin
          Result := 0;
          Break;
        end;
      except
        on E: Exception do
        begin
          Spinner.Stop;
          TConsole.WriteLn('Connection error: ' + E.Message, ccRed);
          Inc(Attempts);
          if Attempts >= MAX_CONNECTION_ATTEMPTS then
          begin
            TConsole.WriteLn('Too many connection attempts', ccRed);
            Break;
          end;
          Sleep(100);
          Spinner.Start;
        end;
      end;
      Inc(Attempts);
    end;
  finally
    Spinner.Stop;
    FreeAndNil(RAM);
  end;

  TConsole.WriteLn('');
end;

initialization

  Flash := TFlashCommand.Create('flash', 'flash file(s)');
  Flash.AddArrayParameter('-i', '--input', 'input files');
  Flash.AddPathParameter('-l', '--list', 'input files list');
  Flash.AddArrayParameter('', '--versions', 'QCFM version(s)', False, '1,2');
  Flash.AddPathParameter('-r', '--loaders', 'ram-loaders directory', False, 'loaders');
  Flash.AddIntegerParameter('-d', '--delay', 'RAM-loader delay', False, '1000');

  Loader := TLoaderCommand.Create('loader', 'probe all loaders');
  Loader.AddIntegerParameter('-d', '--delay', 'RAM-loader delay', False, '1000');

  Info := TInfoCommand.Create('info', 'Show connected device info');
  Info.AddIntegerParameter('-d', '--delay', 'RAM-loader delay', False, '1000');

  Nuke := TNukeCommand.Create('nuke', 'Nuke device');

end.
