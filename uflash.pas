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
  CLI.Progress,      // Optional: Progress indicators
  CLI.Console        // Optional: Colored console output
  ;

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
    procedure DisplayBlocklist(const title: string; const Data: TBytes);
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
  uMisc,
  LCLType;

const
  MAX_CONNECTION_ATTEMPTS = 50;
  DEFAULT_LOADER_DELAY = 1000;
  MCT_SIGNATURE = $92be564a;


function TLoaderCommand.Execute: integer;
var
  RAM: TRamLoader;
begin
  Result := 1;
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

  // ASCII символ (0xxxxxxx)
  if B <= $7F then
  begin
    Result := True;
    Exit;
  end;

  // Визначаємо кількість байтів у UTF-8 послідовності
  if (B and $E0) = $C0 then
    ExpectedBytes := 2      // 110xxxxx
  else if (B and $F0) = $E0 then
    ExpectedBytes := 3      // 1110xxxx
  else if (B and $F8) = $F0 then
    ExpectedBytes := 4      // 11110xxx
  else
    Exit; // Невалідний стартовий байт

  // Перевіряємо чи є достатньо байтів
  if StartPos + ExpectedBytes > Length(Buffer) then
    Exit;

  SeqLength := ExpectedBytes;

  // Перевіряємо продовжуючі байти (10xxxxxx)
  for I := 1 to ExpectedBytes - 1 do
  begin
    if (Buffer[StartPos + I] and $C0) <> $80 then
      Exit;
  end;

  // Перевіряємо на overlong encoding та invalid code points
  case ExpectedBytes of
    2: Result := (B >= $C2);
    // Мінімальне значення для 2-байтової послідовності
    3: Result := not ((B = $E0) and ((Buffer[StartPos + 1] and $E0) = $80)); // Overlong
    4: Result := not ((B = $F0) and ((Buffer[StartPos + 1] and $F0) = $80)); // Overlong
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
    // Нульовий байт = бінарний файл
    if Buffer[I] = 0 then
      Exit;

    // ASCII контрольні символи (дозволяємо TAB, LF, CR)
    if (Buffer[I] < 32) and not (Buffer[I] in [9, 10, 13]) then
      Exit;

    // Якщо це можливо початок UTF-8 послідовності
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
        // Невалідна UTF-8 послідовність
        // Якщо забагато невалідних послідовностей, вважаємо файл бінарним
        if (TotalMultiByteCount > 10) and (ValidUTF8Count * 100 div TotalMultiByteCount < 80) then
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
  // BOM сигнатури
  UTF8_BOM: array[0..2] of byte = ($EF, $BB, $BF);
  UTF16LE_BOM: array[0..1] of byte = ($FF, $FE);
  UTF16BE_BOM: array[0..1] of byte = ($FE, $FF);
var
  Stream: TFileStream;
  Buffer: array[0..MaxCheckSize - 1] of byte;
  BytesRead: integer;
  I: integer;
  BOM: array[0..2] of byte;
begin
  Result := False;

  if not FileExists(FileName) then
    Exit;

  try
    Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
    try
      // Порожній файл вважаємо текстовим
      if Stream.Size = 0 then
        Exit(True);

      // Перевіряємо BOM
      FillChar(BOM, SizeOf(BOM), 0);
      BytesRead := Stream.Read(BOM, SizeOf(BOM));

      // UTF-8 BOM
      if (BytesRead >= 3) and CompareMem(@BOM, @UTF8_BOM, 3) then
        Exit(True);

      // UTF-16 LE BOM
      if (BytesRead >= 2) and CompareMem(@BOM, @UTF16LE_BOM, 2) then
        Exit(True);

      // UTF-16 BE BOM
      if (BytesRead >= 2) and CompareMem(@BOM, @UTF16BE_BOM, 2) then
        Exit(True);

      // Повертаємось на початок для перевірки вмісту
      Stream.Position := 0;
      BytesRead := Stream.Read(Buffer, SizeOf(Buffer));

      // Перевіряємо байти на текстовість з UTF-8 валідацією
      if not IsValidTextContent(Buffer, BytesRead) then
        Exit(False);

      Result := True;

    finally
      Stream.Free;
    end;
  except
    // У випадку помилки доступу до файлу
    Result := False;
  end;
end;

function TFlashCommand.Execute: integer;
var
  FL: TStringList;
  tmpA: array of string;
  tmps, tmps2, tmps3, tmps4, tmps5: string;
  i, k, ver, runLoaderDelay, attempts: integer;
  vers: TStringList;
  spinner: IProgressIndicator;
  RAM: TRamLoader;
  FileName: string;
  flashSuccess: boolean;
begin
  Result := 0;
  ver := 2; // Default value
  RAM := nil; // Initialize to nil for safety
  vers := nil; // Initialize to nil

  // Get parameter values
  GetParameterValue('--input', tmps);
  GetParameterValue('--list', tmps2);
  GetParameterValue('--versions', tmps4);
  GetParameterValue('--loaders', tmps5);

  // Get delay parameter with default value
  if GetParameterValue('--delay', tmps3) then
    runLoaderDelay := StrToIntDef(tmps3, 1000)
  else
    runLoaderDelay := 1000;

  // Process version flags
  if GetParameterValue('--versions', tmps4) and (tmps4 <> '') then
  begin
    ver := 0;
    vers := TStringList.Create;
    try
      vers.AddCommaText(tmps4);
      vers.Sorted := True;
      if vers.IndexOf('1') >= 0 then ver := ver + 1;
      if vers.IndexOf('2') >= 0 then ver := ver + 2;
    finally
      FreeAndNil(vers); // Corrected to use FreeAndNil
    end;
  end;

  // Validate version
  if not (ver in [1, 2, 3]) then
    ver := 3;

  FL := TStringList.Create;
  try
    // Load files from list file if specified
    if (tmps2 <> '') then
    begin
      tmps2 := ExpandFileName(tmps2);
      if FileExists(tmps2) and IsTextFile(tmps2) and (FileSize(tmps2) < 8192) then
        FL.LoadFromFile(tmps2)
      else if FileExists(tmps2) then
        TConsole.WriteLn('Warning: list file looks like binary or too big (more than 8k). Skipping',
          ccYellow);
    end;

    // Add files from input parameter
    if tmps <> '' then
      FL.AddCommaText(tmps);

    // Filter and validate files
    for i := FL.Count - 1 downto 0 do
    begin
      tmpA := SplitString(FL[i], '=');
      fileName := ExpandFileName(tmpA[0]);

      if not FileExists(FileName) then
      begin
        TConsole.WriteLn('Warning: File not found - ' + FileName, ccYellow);
        FL.Delete(i);
      end
      else
        FL.Strings[i] := FileName;

    end;

    if FL.Count = 0 then
    begin
      TConsole.WriteLn('Error: no valid files found', ccRed);
      Result := 10;
      Exit;
    end;

    TConsole.WriteLn('Connecting to BootROM...');

    spinner := CreateSpinner(ssDots);
    RAM := TRamLoader.Create(tmps5);
    try
      attempts := 0;
      spinner.Start;

      // Connection attempt loop
      while attempts <= 50 do
      begin
        try
          if RAM.ConnectToBB(runLoaderDelay, True) then
            Break;
        except
          on E: Exception do
          begin
            TConsole.WriteLn('Connection error: ' + E.Message, ccRed);
            Inc(attempts);
            if attempts > 50 then
            begin
              TConsole.WriteLn('Too many connection attempts', ccRed);
              Result := 11;
              Exit;
            end;
            // Add small delay between retries
            Sleep(100);
          end;
        end;
        Inc(attempts);
      end;

      if attempts > 50 then
      begin
        TConsole.WriteLn('Failed to connect after maximum attempts', ccRed);
        Result := 11;
        Exit;
      end;

      // Flash files
      TConsole.WriteLn('Flashing ' + IntToStr(FL.Count) + ' files...');
      flashSuccess := True;
      for i := 0 to FL.Count - 1 do
      begin
        tmps := ExtractFileName(FL[i]);
        if fileName.EndsWith('!') then
          tmps := tmps.TrimEnd('!');
        TConsole.WriteLn('Flashing: ' + tmps);
        k := RAM.FlashFile(FL[i], ver);
        if k < 0 then
        begin
          flashSuccess := False;
          if k = -3 then break;
        end;

      end;

      // Reboot phone
      TConsole.WriteLn('Rebooting phone...');
      RAM.RebootPhone;
      TConsole.WriteLn('Flash completed successfully!', ccGreen);

    finally
      spinner.Stop;
      FreeAndNil(RAM); // Also using FreeAndNil for RAM
    end;

  finally
    FreeAndNil(FL); // Using FreeAndNil for FL as well for consistency
  end;
end;

function TInfoCommand.Execute: integer;
var
  RAM: TRamLoader;
  delayParam, loadersParam: string;
  spinner: IProgressIndicator;
  runLoaderDelay: integer;
  tmpData: TBytes;
  Stream: TMemoryStream;
  sl: TStringList;
begin
  Result := 0;
  RAM := nil;
  Stream := nil;

  try
    // Ініціалізація параметрів
    GetParameterValue('--loaders', loadersParam);
    GetParameterValue('--delay', delayParam);

    runLoaderDelay := StrToIntDef(delayParam, DEFAULT_LOADER_DELAY);

    RAM := TRamLoader.Create(loadersParam);

    // Підключення до BootROM
    if not ConnectToBootROM(RAM, runLoaderDelay) then
    begin
      Result := 11;
      Exit;
    end;

    // Виведення основної інформації про пристрій
    DisplayDeviceInfo(RAM);

    // Виведення інформації про BootROM
    DisplayBootROMInfo(RAM);

    // Обробка MCT даних
    Stream := TMemoryStream.Create;
    ProcessMCTData(RAM, Stream);

    // Виведення інформації про Flash
    DisplayFlashInfo(RAM);

    // Виведення інформації про DRAM
    DisplayDRAMInfo(RAM);

    // Виведення інформації про брендинг та OS
    DisplayBrandingAndOSInfo(RAM);

    // Виведення блокованих списків
    TConsole.WriteLn('');
    DisplayBlocklist('OS Blocklist:', RAM.Loader.BlockedOS);
    DisplayBlocklist('Radio Blocklist:', RAM.Loader.BlockedRadio);
    //RAM.Loader.EraseMCT;
(*
    tmpData := RAM.Loader.GetBlog;
    if Length(tmpData) > 0 then
    begin
      Stream.Clear;
      Stream.WriteBuffer(tmpData[0], Length(tmpData));
      Stream.SaveToFile('bootrom.log');
    end;

    tmpData := RAM.Loader.GetLAL;
    if Length(tmpData) > 0 then
    begin
      Stream.Clear;
      Stream.WriteBuffer(tmpData[0], Length(tmpData));
      Stream.SaveToFile('lal.log');
    end;

    tmpData := RAM.Loader.BugdispLog;
    if Length(tmpData) > 0 then
    begin
      Stream.Clear;
      Stream.WriteBuffer(tmpData[0], Length(tmpData));
      Stream.SaveToFile('bugdisp.log');
    end;

    tmpData := RAM.Loader.GetOsBoot;
    if Length(tmpData) > 0 then
    begin
      Stream.Clear;
      Stream.WriteBuffer(tmpData[0], Length(tmpData));
      Stream.SaveToFile('osboot.log');
    end;
*)
    // Перезавантаження пристрою
    RAM.RebootPhone;

  finally
    FreeAndNil(Stream);
    FreeAndNil(RAM);
  end;
end;


// Допоміжні методи для розділення логіки

function TInfoCommand.ConnectToBootROM(RAM: TRamLoader; delay: integer): boolean;
var
  spinner: IProgressIndicator;
  attempts: integer;
begin
  Result := False;
  TConsole.WriteLn('Connecting to BootROM...');

  spinner := CreateSpinner(ssDots);
  attempts := 0;

  repeat
  try
    spinner.Start;
    if RAM.ConnectToBB(delay) then
    begin
      Result := True;
      Break;
    end;
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Connection error: ' + E.Message, ccRed);
      Inc(attempts);
      if attempts >= MAX_CONNECTION_ATTEMPTS then
      begin
        TConsole.WriteLn('Too many connection attempts', ccRed);
        Break;
      end;
    end;
  end;
  until False;

  spinner.Stop;
  TConsole.WriteLn('');
  TConsole.WriteLn('');
end;

procedure TInfoCommand.DisplayDeviceInfo(RAM: TRamLoader);
begin
  TConsole.WriteLn('QNX Device Info:');
  TConsole.WriteLn(Format('  PIN:               %.8X', [int64(RAM.Loader.PIN)]));
  TConsole.WriteLn(Format('  BSN:               %d', [int64(RAM.Loader.BSN)]));
  TConsole.WriteLn('');
end;

procedure TInfoCommand.DisplayBootROMInfo(RAM: TRamLoader);
var
  HWID: THW_Override;
  tmpData: TBytes;
  BRMetrics: PBRMetrics;
begin
  tmpData := RAM.Loader.HWID_OVERRIDE;
  if Length(tmpData) = 8 then
    HWID := PHW_Override(@tmpData[0])^;

  BRMetrics := @PBRMetrics(@RAM.BootromInfo[4])^;

  with BRMetrics^ do
  begin
    TConsole.WriteLn(Format('Bootrom Version:   %d.%d.%d.%d',
      [TFourInts(BR_ver)[3], TFourInts(BR_ver)[2], TFourInts(BR_ver)[1], TFourInts(BR_ver)[0]]));
    TConsole.WriteLn(Format('  Hardware ID:       0x%.8X %s',
      [int64(RAM.ModelID), ReadCString(HardwareName)]));
    TConsole.WriteLn(Format('  HW ID Override:    0x%.8X (OSTypes: 0x%.8X)',
      [int64(HWID.ID), int64(HWID.OS)]));
    TConsole.WriteLn(Format('  Hardware OS ID:    0x%.8X', [int64(HWOSID)]));
    TConsole.WriteLn(Format('  BR ID:             0x%.8X', [int64(BRID)]));
    TConsole.WriteLn(Format('  Metrics Version:   %d.%d', [(version shr 16) and $FF, version and $FF]));
    TConsole.WriteLn(Format('  Build Date:        %s', [ReadCString(BuildDate)]));
    TConsole.WriteLn(Format('  Build Time:        %s', [ReadCString(BuildTime)]));
    TConsole.WriteLn(Format('  Build User:        %s', [ReadCString(BuildUser)]));
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
    TConsole.WriteLn(Format('  Supported Options: 0x%.8X', [int64(SupportedOptions)]));
    TConsole.WriteLn(Format('  Drivers:           0x%.8X', [int64(Drivers)]));
    TConsole.WriteLn(Format('  Processor:         0x%.8X', [int64(Processor)]));
    TConsole.WriteLn(Format('  FlashID:           0x%.8X', [int64(FlashID)]));
    TConsole.WriteLn(Format('  LDR Blocks:        0x%.8X', [int64(LDRBlocks)]));
    TConsole.WriteLn(Format('  Bootrom Size:      0x%.8X', [int64(BootromSize)]));
    TConsole.WriteLn(Format('  Persist Data Addr: 0x%.8X', [int64(PersistAddr)]));
  end;
end;

procedure TInfoCommand.DisplayHardwareInfo(BRMetrics: PBRMetrics);
begin
  with BRMetrics^ do
  begin
    if HWV_off <> 0 then
      TConsole.WriteLn('  External MCT/HWV:  Enabled')
    else
      TConsole.WriteLn('  External MCT/HWV:  Disabled');
  end;
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
      with OldestMFI do
        TConsole.WriteLn(Format('    Oldest Allowed MFI:  %d/%d/%d', [Month, Day, Year]));
      with OldestSFI do
        TConsole.WriteLn(Format('    Oldest Allowed SFI:  %d/%d/%d', [Month, Day, Year]));
    end;
  end;
end;

procedure TInfoCommand.DisplayHWVInfo(BRMetrics: PBRMetrics);
var
  i: integer;
begin
  with BRMetrics^ do
  begin
    if HWV_off > 0 then
    begin
      TConsole.WriteLn('');
      TConsole.WriteLn('  HWV:');
      for i := 0 to High(HVW) do
      begin
        if HVW[i].ID = $FF then
          Break;
        TConsole.WriteLn('    ' + HWVtoString(HVW[i]));
      end;
    end;
  end;
end;

procedure TInfoCommand.ProcessMCTData(RAM: TRamLoader; Stream: TMemoryStream);
var
  i, p: integer;
  MCT: TMCTParsed;
  tmpData: TBytes;
begin
  // Пошук MCT сигнатури
  p := FindMCTSignature(RAM.BootromInfo);

  if p > 0 then
  begin
    TConsole.WriteLn('');
    i := Length(RAM.BootromInfo) - p;
    Stream.WriteBuffer(RAM.BootromInfo[p], i);
    Stream.Position := 0;
    MCT := ParseMCTStream(Stream);
    ShowParsedMCT(MCT);
    Stream.Clear;

    tmpData := RAM.Loader.GetMCT;
    if Length(tmpData) > 0 then
    begin
      TConsole.WriteLn('');
      Stream.WriteBuffer(tmpData[0], Length(tmpData));
      Stream.Position := 0;
      MCT := ParseMCTStream(Stream);
      ShowParsedMCT(MCT, True);
    end;
  end;
end;

function TInfoCommand.FindMCTSignature(const Data: TBytes): integer;
var
  i: integer;
begin
  Result := 0;
  i := SizeOf(TBRMetrics) + 4;

  while i < High(Data) do
  begin
    if PDword(@Data[i])^ = MCT_SIGNATURE then
    begin
      Result := i;
      Break;
    end;
    Inc(i, 4);
  end;
end;

procedure TInfoCommand.DisplayFlashInfo(RAM: TRamLoader);
var
  flashData: TBytes;
begin
  flashData := RAM.Loader.FlashRegionsInfo;
  if Length(flashData) >= SizeOf(TFlashInfo) then
  begin
    with PFlashInfo(@flashData[0])^ do
    begin
      TConsole.WriteLn('');
      TConsole.WriteLn('Flash:');
      TConsole.WriteLn(Format('  Flash ID:              NAND blocks 0-%d', [Blocks]));
      TConsole.WriteLn(Format('  Device ID:             0x%.2X', [DeviceID]));
      TConsole.WriteLn(Format('  Vendor ID:             0x%.2X', [VendorID]));
      TConsole.WriteLn(Format('  Manufacturer Name:     %s', [EMMCVendorByID(VendorID)]));
      TConsole.WriteLn(Format('  Product Name:          %s', [ReadCString(Name)]));
      TConsole.WriteLn(Format('  Product Serial Number: 0x%.8X', [int64(Serial)]));
      TConsole.WriteLn('  MMC Partition Info:');
      TConsole.WriteLn(Format('    User:                %d KB', [user]));
    end;
  end;
end;

procedure TInfoCommand.DisplayDRAMInfo(RAM: TRamLoader);
var
  dramData: TBytes;
begin
  dramData := RAM.Loader.DRAMInfo;
  if Length(dramData) >= SizeOf(TDRAM_Info) then
  begin
    with PDRAM_Info(@dramData[0])^ do
    begin
      TConsole.WriteLn('');
      TConsole.WriteLn('DRAM:');
      TConsole.WriteLn(Format('  Size:              %d MB', [Size div (1024 * 1024)]));
      TConsole.WriteLn(Format('  VendorID:          0x%X', [vendor]));
      TConsole.WriteLn(Format('  Vendor Name:       %s', [DRAMVendorByID(vendor)]));
      TConsole.WriteLn(Format('  Revision:          0x%X', [revision]));
    end;
  end;
end;

procedure TInfoCommand.DisplayBrandingAndOSInfo(RAM: TRamLoader);
var
  osData: TBytes;
begin
  TConsole.WriteLn('');
  TConsole.WriteLn('Branding:');
  TConsole.WriteLn(Format('  ECID:              %d', [RAM.Loader.VendorID]));

  osData := RAM.Loader.OSMetrics;
  if Length(osData) >= SizeOf(TOSMetrics) then
  begin
    with POSMetrics(@osData[0])^ do
    begin
      TConsole.WriteLn('');
      TConsole.WriteLn(Format('OS Version:          %s', [VersionToString(os_version)]));
      TConsole.WriteLn(Format('  Hardware ID:       0x%.8X %s',
        [int64(hardware_id), ReadCString(device_string)]));
      TConsole.WriteLn(Format('  Metrics Version:   %d.%d', [version shr 16, version and $FF]));
      TConsole.WriteLn(Format('  Build Date:        %s', [ReadCString(build_date)]));
      TConsole.WriteLn(Format('  Build Time:        %s', [ReadCString(build_time)]));
      TConsole.WriteLn(Format('  Build User:        %s', [ReadCString(build_user)]));
      TConsole.WriteLn(Format('  OS Address:        0x%.8X-0x%.8X',
        [int64(load_base_ptr), int64(load_end_ptr - 1)]));
    end;
  end;
end;

procedure TInfoCommand.DisplayBlocklist(const title: string; const Data: TBytes);
var
  sl: TStringList;
  item: string;
begin
  sl := DecodeBlocked(Data);
  if sl <> nil then
  begin
    try
      TConsole.WriteLn(title);
      for item in sl do
        TConsole.WriteLn(item);
    finally
      FreeAndNil(sl);
    end;
  end;
end;


function TNukeCommand.Execute: integer;
var
  spinner: IProgressIndicator;
  attempts: integer;
  RAM: TRamLoader;
begin
  TConsole.WriteLn('Connecting to BootROM...');

  spinner := CreateSpinner(ssDots);
  attempts := 0;
  RAM := TRamLoader.Create;
  try

    repeat
    try
      spinner.Start;
      if RAM.ConnectToBB(-1) then
      begin
        Result := 0;
        Break;
      end;
    except
      on E: Exception do
      begin
        TConsole.WriteLn('Connection error: ' + E.Message, ccRed);
        Inc(attempts);
        if attempts >= MAX_CONNECTION_ATTEMPTS then
        begin
          TConsole.WriteLn('Too many connection attempts', ccRed);
          Break;
        end;
      end;
    end;
    until False;
    spinner.Stop;
    TConsole.WriteLn('');
    TConsole.WriteLn('');

  finally
    FreeAndNil(RAM);
  end;

end;


// Допоміжні методи для розділення логіки

initialization

  Flash := TFlashCommand.Create('flash', 'flash file(s)');
  Flash.AddArrayParameter('-i', '--input', 'input files');
  Flash.AddPathParameter('-l', '--list', 'input files list');
  Flash.AddArrayParameter('-v', '--versions', 'QCFM version(s)', False, '1,2');
  Flash.AddPathParameter('-r', '--loaders', 'ram-loaders directory', False, 'loaders');
  Flash.AddIntegerParameter('-d', '--delay', 'RAM-loader delay', False, '1000');
  Loader := TLoaderCommand.Create('loader', 'probe all loaders');
  Loader.AddIntegerParameter('-d', '--delay', 'RAM-loader delay', False, '1000');
  Info := TInfoCommand.Create('info', 'Show connected device info');
  Info.AddIntegerParameter('-d', '--delay', 'RAM-loader delay', False, '1000');

  Nuke := TNukeCommand.Create('nuke', 'Nuke device');

end.
