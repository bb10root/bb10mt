unit RamLoader;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, bbusb, bbLoader;
  // РЈРЅС–РІРµСЂСЃР°Р»СЊРЅР° СЃС‚СЂСѓРєС‚СѓСЂР° РґР»СЏ РїРѕРІРЅРѕС— С–РЅС„РѕСЂРјР°С†С–С— РїСЂРѕ РїСЂРёСЃС‚СЂС–Р№
type
  TFullDeviceInfo = record
    ID: longword;
    ModelCode: string;
    ModelName: string;
    FullName: string;
    Category: string;
  end;


  TRamLoader = class
  private
    fBB: TBBUSB;
    fBBLdr: TBBLoader;
    FModelID: cardinal;
    FLdrDir: string;
    FBRomInfo: TBytes;
    procedure SafeCloseAndFree(var BBUSB: TBBUSB);
    procedure SafeFreeLoader(var Loader: TBBLoader);
    function IsValidSignature(const Data: TBytes): boolean;
    function isSignedLoader(const Data: TBytes): boolean;
    function isValidLoader(const Data: TBytes): boolean;
    function FindLoaderResource(const ID: string): string;
    function ModelToRes(modelId: cardinal): string;
    function ForceLoader(const fName: string; var Data: TBytes): boolean;
    function LoadLoader(ModelID: cardinal; var Data: TBytes): boolean;
    function WaitForLoaderMode(timeoutMs: integer): boolean;
    procedure SendAndRunLoader(const Data: TBytes; runDelay: integer);
    function InitializeLoaderInterface: boolean;
    function probeLoader(const ldr: string): integer;
  public
    constructor Create(Dir: string = '');
    destructor Destroy; override;
    function ConnectToBB(const runLoaderDelay: integer = 1000; verbose: boolean = False): boolean;
    procedure RebootPhone;
    function FlashFile(fName: string; ver: byte = 2): integer;
    function TryGetDeviceInfoByID(const aID: longword; out aFullInfo: TFullDeviceInfo): boolean;
    procedure ProbeLoaders;
    function IDtoADDR(const ID: cardinal): cardinal;

    property ModelID: cardinal read FModelID;
    property Loader: TBBLoader read fBBLdr;
    property BootromInfo: TBytes read FBRomInfo;
  end;


implementation

uses
  qcfm,
  IniFiles,
  uInfo,
  uArchive,
  FileUtil,
  LazFileUtils,
  Math,
  uMisc,
  CLI.Interfaces,    // Core interfaces
  CLI.Command,       // Base command implementation
  CLI.Progress,      // Optional: Progress indicators
  CLI.Console;       // Optional: Colored console output

type
  // РЎС‚СЂСѓРєС‚СѓСЂР° РґР»СЏ Р·Р±РµСЂС–РіР°РЅРЅСЏ Р·Р°РіР°Р»СЊРЅРѕС— С–РЅС„РѕСЂРјР°С†С–С— РїСЂРѕ РјРѕРґРµР»СЊ
  TModelInfo = record
    ModelName: string;
    FullName: string;
    Category: string;
  end;

  // РћРЅРѕРІР»РµРЅР° СЃС‚СЂСѓРєС‚СѓСЂР° РґР»СЏ РїСЂРёСЃС‚СЂРѕСЋ, С‰Рѕ РјС–СЃС‚РёС‚СЊ С–РЅРґРµРєСЃ РјРѕРґРµР»С–
  TDeviceInfo = record
    ID: longword;
    ModelCode: string;
    ModelIndex: byte; // Byte (0..255) РґРѕСЃС‚Р°С‚РЅСЊРѕ РґР»СЏ С–РЅРґРµРєСЃС–РІ
  end;


const
  DeviceModels: array[0..14] of TModelInfo = (
    (ModelName: 'Classic'; FullName: 'BlackBerry Classic'; Category: 'Bold'),     // 0
    (ModelName: 'P''9983'; FullName: 'PORSCHE DESIGN P''9983 BlackBerry'; Category: 'Bold'),     // 1
    (ModelName: 'Q10'; FullName: 'BlackBerry Q10'; Category: 'Bold'),     // 2
    (ModelName: 'Q5'; FullName: 'BlackBerry Q5'; Category: 'Curve'),    // 3
    (ModelName: 'Passport'; FullName: 'BlackBerry Passport'; Category: 'Passport'), // 4
    (ModelName: 'Z30'; FullName: 'BlackBerry Z30'; Category: 'Touch'),    // 5
    (ModelName: 'Z3'; FullName: 'BlackBerry Z3'; Category: 'Touch'),    // 6
    (ModelName: 'P''9982'; FullName: 'PORSCHE DESIGN P''9982 BlackBerry'; Category: 'Touch'),    // 7
    (ModelName: 'Z10'; FullName: 'BlackBerry Z10'; Category: 'Touch'),    // 8
    (ModelName: 'Unknown'; FullName: 'Unknown'; Category: 'Unknown'),  // 9
    (ModelName: 'Leap'; FullName: 'BlackBerry Leap'; Category: 'Touch'),    // 10
    (ModelName: 'Unknown'; FullName: 'BlackBerry Unknown'; Category: 'Unknown'),  // 11
    (ModelName: 'Playbook'; FullName: 'BlackBerry Playbook'; Category: 'Playbook'), // 12
    (ModelName: 'Anonymous'; FullName: 'BlackBerry Unknown'; Category: 'Unknown'),  // 13
    (ModelName: 'BlackBerry 10 Dev Alpha'; FullName: 'BlackBerry 10 Dev Alpha'; Category: 'Unknown') // 14
    );

const
  BB10Devices: array[0..52] of TDeviceInfo = (
    (ID: $9600270a; ModelCode: 'SQC100-1'; ModelIndex: 0), // Classic
    (ID: $9400270a; ModelCode: 'SQC100-2'; ModelIndex: 0), // Classic
    (ID: $9500270a; ModelCode: 'SQC100-3'; ModelIndex: 0), // Classic
    (ID: $9700270a; ModelCode: 'SQC100-4'; ModelIndex: 0), // Classic
    (ID: $9c00270a; ModelCode: 'SQC100-5'; ModelIndex: 0), // Classic
    (ID: $8f00270a; ModelCode: 'SQK100-1'; ModelIndex: 1), // P'9983
    (ID: $8e00270a; ModelCode: 'SQK100-2'; ModelIndex: 1), // P'9983
    (ID: $8400270a; ModelCode: 'SQN100-1'; ModelIndex: 2), // Q10
    (ID: $8500270a; ModelCode: 'SQN100-2'; ModelIndex: 2), // Q10
    (ID: $8600270a; ModelCode: 'SQN100-3'; ModelIndex: 2), // Q10
    (ID: $8c00270a; ModelCode: 'SQN100-4'; ModelIndex: 2), // Q10
    (ID: $8700270a; ModelCode: 'SQN100-5'; ModelIndex: 2), // Q10
    (ID: $84002a0a; ModelCode: 'SQR100-1'; ModelIndex: 3), // Q5
    (ID: $85002a0a; ModelCode: 'SQR100-2'; ModelIndex: 3), // Q5
    (ID: $86002a0a; ModelCode: 'SQR100-3'; ModelIndex: 3), // Q5
    (ID: $87002c0a; ModelCode: 'SQW100-1'; ModelIndex: 4), // Passport
    (ID: $85002c0a; ModelCode: 'SQW100-2'; ModelIndex: 4), // Passport
    (ID: $84002c0a; ModelCode: 'SQW100-3'; ModelIndex: 4), // Passport
    (ID: $8f002c0a; ModelCode: 'SQW100-4'; ModelIndex: 4), // Passport
    (ID: $8c00240a; ModelCode: 'STA100-1'; ModelIndex: 5), // Z30
    (ID: $8d00240a; ModelCode: 'STA100-2'; ModelIndex: 5), // Z30
    (ID: $8e00240a; ModelCode: 'STA100-3'; ModelIndex: 5), // Z30
    (ID: $8f00240a; ModelCode: 'STA100-4'; ModelIndex: 5), // Z30
    (ID: $9500240a; ModelCode: 'STA100-5'; ModelIndex: 5), // Z30
    (ID: $b500240a; ModelCode: 'STA100-6'; ModelIndex: 5), // Z30
    (ID: $04002e07; ModelCode: 'STJ100-1'; ModelIndex: 6), // Z3
    (ID: $05002e07; ModelCode: 'STJ100-2'; ModelIndex: 6), // Z3
    (ID: $a500240a; ModelCode: 'STK100-1'; ModelIndex: 7), // P'9982
    (ID: $a600240a; ModelCode: 'STK100-2'; ModelIndex: 7), // P'9982
    (ID: $04002607; ModelCode: 'STL100-1'; ModelIndex: 8), // Z10
    (ID: $8700240a; ModelCode: 'STL100-2'; ModelIndex: 8), // Z10
    (ID: $8500240a; ModelCode: 'STL100-3'; ModelIndex: 8), // Z10
    (ID: $8400240a; ModelCode: 'STL100-4'; ModelIndex: 8), // Z10
    (ID: $05002e0a; ModelCode: 'STM100-1'; ModelIndex: 9), // Unknown
    (ID: $04002e0a; ModelCode: 'STM100-2'; ModelIndex: 9), // Unknown
    (ID: $07002e0a; ModelCode: 'STR100-1'; ModelIndex: 10), // Leap
    (ID: $06002e0a; ModelCode: 'STR100-2'; ModelIndex: 10), // Leap
    (ID: $86002c0a; ModelCode: 'Unknown'; ModelIndex: 4), // Passport
    (ID: $8c002c0a; ModelCode: 'Unknown'; ModelIndex: 9), // Unknown
    (ID: $8d002c0a; ModelCode: 'Unknown'; ModelIndex: 4), // Passport
    (ID: $8e002c0a; ModelCode: 'Unknown'; ModelIndex: 4), // Passport
    (ID: $a400080a; ModelCode: 'Unknown'; ModelIndex: 11),// BlackBerry Unknown
    (ID: $ae00240a; ModelCode: 'Unknown'; ModelIndex: 11),// BlackBerry Unknown
    (ID: $af00240a; ModelCode: 'Unknown'; ModelIndex: 11),// BlackBerry Unknown
    (ID: $b400240a; ModelCode: 'Unknown'; ModelIndex: 11),// BlackBerry Unknown
    (ID: $b600240a; ModelCode: 'Unknown'; ModelIndex: 11),// BlackBerry Unknown
    (ID: $bc00240a; ModelCode: 'Unknown'; ModelIndex: 11),// BlackBerry Unknown
    (ID: $06001a06; ModelCode: 'P100-16WF'; ModelIndex: 12),// Playbook
    (ID: $0c001a06; ModelCode: 'P150-32LT1'; ModelIndex: 12),// Playbook
    (ID: $0d001a06; ModelCode: 'P150-32LT2'; ModelIndex: 12),// Playbook
    (ID: $0e001a06; ModelCode: 'P150-32HS'; ModelIndex: 12),// Playbook
    (ID: $8500080a; ModelCode: 'PRO100-1'; ModelIndex: 13),// Anonymous
    (ID: $04002307; ModelCode: 'PRO100-2'; ModelIndex: 14) // Dev Alpha
    );


var
  LoaderMap: TMemIniFile = nil;
  Loaders: TMyArcReader = nil;

  { TRamLoader }

constructor TRamLoader.Create(Dir: string = '');
begin
  inherited Create;
  fBB := nil;
  fBBLdr := nil;
  FModelID := 0;
  if Dir = '' then
    FldrDir := GetExeDirectory + 'loaders'
  else
    FldrDir := Dir;
  SetLength(FBRomInfo, 0);
end;

destructor TRamLoader.Destroy;
begin
  SetLength(FBRomInfo, 0);
  SafeFreeLoader(fBBLdr);
  SafeCloseAndFree(fBB);
  inherited Destroy;
end;

procedure TRamLoader.SafeCloseAndFree(var BBUSB: TBBUSB);
begin
  if Assigned(BBUSB) then
  begin
    try
      BBUSB.Close;
    except
      // Ignore close errors
    end;
    FreeAndNil(BBUSB);
  end;
end;

procedure TRamLoader.SafeFreeLoader(var Loader: TBBLoader);
begin
  if Assigned(Loader) then
    FreeAndNil(Loader);
end;

{
  Р¤СѓРЅРєС†С–СЏ РґР»СЏ РїРѕС€СѓРєСѓ РїРѕРІРЅРѕС— С–РЅС„РѕСЂРјР°С†С–С— РїСЂРѕ РїСЂРёСЃС‚СЂС–Р№ Р·Р° Р№РѕРіРѕ ID.
  РџР°СЂР°РјРµС‚СЂРё:
    - aID: ID РїСЂРёСЃС‚СЂРѕСЋ, СЏРєРёР№ РїРѕС‚СЂС–Р±РЅРѕ Р·РЅР°Р№С‚Рё.
    - aFullInfo: Р·РјС–РЅРЅР°, РІ СЏРєСѓ Р±СѓРґРµ Р·Р°РїРёСЃР°РЅРѕ РїРѕРІРЅСѓ С–РЅС„РѕСЂРјР°С†С–СЋ (СЏРєС‰Рѕ Р·РЅР°Р№РґРµРЅРѕ).
  РџРѕРІРµСЂС‚Р°С”:
    - True, СЏРєС‰Рѕ РїСЂРёСЃС‚СЂС–Р№ Р· С‚Р°РєРёРј ID С–СЃРЅСѓС”.
    - False, СЏРєС‰Рѕ РїСЂРёСЃС‚СЂС–Р№ РЅРµ Р·РЅР°Р№РґРµРЅРѕ.
}
function TRamLoader.TryGetDeviceInfoByID(const aID: longword; out aFullInfo: TFullDeviceInfo): boolean;
var
  Device: TDeviceInfo;
  Model: TModelInfo;
begin
  Result := False; // Р—Р° Р·Р°РјРѕРІС‡СѓРІР°РЅРЅСЏРј РїСЂРёСЃС‚СЂС–Р№ РЅРµ Р·РЅР°Р№РґРµРЅРѕ
  aFullInfo := Default(TFullDeviceInfo); // РћС‡РёС‰СѓС”РјРѕ РІРёС…С–РґРЅСѓ СЃС‚СЂСѓРєС‚СѓСЂСѓ

  // 1. РЁСѓРєР°С”РјРѕ РїСЂРёСЃС‚СЂС–Р№ РІ РѕСЃРЅРѕРІРЅРѕРјСѓ РјР°СЃРёРІС–
  for Device in BB10Devices do
  begin
    if Device.ID = aID then
    begin
      // 2. РЇРєС‰Рѕ Р·РЅР°Р№С€Р»Рё, РѕС‚СЂРёРјСѓС”РјРѕ С–РЅС„РѕСЂРјР°С†С–СЋ РїСЂРѕ РјРѕРґРµР»СЊ Р·Р° С–РЅРґРµРєСЃРѕРј
      Model := DeviceModels[Device.ModelIndex];

      // 3. Р—Р°РїРѕРІРЅСЋС”РјРѕ РІРёС…С–РґРЅСѓ СЃС‚СЂСѓРєС‚СѓСЂСѓ TFullDeviceInfo
      aFullInfo.ID := Device.ID;
      aFullInfo.ModelCode := Device.ModelCode;
      aFullInfo.ModelName := Model.ModelName;
      aFullInfo.FullName := Model.FullName;
      aFullInfo.Category := Model.Category;

      Result := True; // РџРѕРІС–РґРѕРјР»СЏС”РјРѕ РїСЂРѕ СѓСЃРїС–С…
      Exit; // Р’РёС…РѕРґРёРјРѕ Р· С„СѓРЅРєС†С–С—, РѕСЃРєС–Р»СЊРєРё РїСЂРёСЃС‚СЂС–Р№ РІР¶Рµ Р·РЅР°Р№РґРµРЅРѕ
    end;
  end;
end;

function TRamLoader.FindLoaderResource(const ID: string): string;
begin
  if Assigned(LoaderMap) then
    Result := LoaderMap.ReadString('Loaders', ID, '')
  else
    Result := '';
end;

function TRamLoader.ModelToRes(modelId: cardinal): string;
var
  idStr: string;
begin
  idStr := Format('%.8x', [int64(modelID)]);
  Result := FindLoaderResource(idStr);
end;

function TRamLoader.ForceLoader(const fName: string; var Data: TBytes): boolean;
var
  iFile: TFileStream;
  s1, s2: int64;
begin
  Result := False;
  if not FileExists(fName) then
    Exit;

  try
    iFile := TFileStream.Create(fName, fmOpenRead or fmShareDenyWrite);
    try
      s1 := iFile.Size;
      if s1 <= 0 then
        Exit;

      SetLength(Data, s1);
      s2 := iFile.Read(Data, s1);
      if s1 > s2 then
        SetLength(Data, s2);
    finally
      iFile.Free;
    end;

    if isValidLoader(Data) then
    begin
      TConsole.WriteLn(Format('loader: %s ', [fName]));
      Result := True;
    end;
  except
    on E: Exception do
    begin
      TConsole.WriteLn(Format('Error loading file %s: %s', [fName, E.Message]), ccRed);
      SetLength(Data, 0);
    end;
  end;
end;

function TRamLoader.LoadLoader(ModelID: cardinal; var Data: TBytes): boolean;
var
  fName, resName: string;
  ldrList: TStringList;
  iFile: TFileStream;
  s1, s2: int64;
begin
  Result := False;

  // Search and verify loader files
  ldrList := FindAllFiles(FldrDir, Format('loader_%.8X*.bin', [int64(ModelID)]), False);
  if Assigned(ldrList) then
  try
    for fName in ldrList do
    begin
      if not FileExists(fName) then
        continue;

      try
        iFile := TFileStream.Create(fName, fmOpenRead or fmShareDenyWrite);
        try
          s1 := iFile.Size;
          if s1 <= 0 then
            continue;

          SetLength(Data, s1);
          s2 := iFile.Read(Data[0], s1);
          if s1 > s2 then
            SetLength(Data, s2);
        finally
          iFile.Free;
        end;

        if isValidLoader(Data) then
        begin
          TConsole.WriteLn(Format('loader: %s ', [fName]));
          Exit(True);
        end;
      except
        on E: Exception do
          TConsole.WriteLn(Format('Error reading loader %s: %s', [fName, E.Message]), ccRed);
      end;
    end;
  finally
    ldrList.Free;
  end;

  // Try resource loader
  resName := ModelToRes(ModelID);
  if (resName <> '') and Assigned(Loaders) and Loaders.FileExists(resName) then
  begin
    try
      if not Loaders.ExtractToBytes(resName, Data) then
      begin
        TConsole.WriteLn('Failed to decompress resource: ' + resName, ccRed);
        Exit(False);
      end;

      if isValidLoader(Data) then
      begin
        TConsole.WriteLn(Format('loader: %s ', [resName]));
        Result := True;
      end;
    except
      on E: Exception do
      begin
        TConsole.WriteLn(Format('Error loading resource %s: %s', [resName, E.Message]), ccRed);
        SetLength(Data, 0);
      end;
    end;
  end;
end;

function TRamLoader.probeLoader(const ldr: string): integer;
const
  MaxAttempts = 200;         // ~10 seconds
  MaxPostRunAttempts = 600;  // ~30 seconds
var
  tmp: TBytes;
  attempts: integer;
  info: PBRMetrics;
  runLoaderDelay: integer = 1000;
  Ini: TIniFile;
begin
  Result := -1;
  TConsole.WriteLn('Connecting to BootROM...');

  if not Assigned(fBB) then
    fBB := TBBUSB.Create;

  // Wait for device in mode 1
  attempts := 0;
  repeat
  try
    if fBB.TryOpen([1, $8001]) then
    begin
      case fBB.id of
        0: begin
          fBB.Close;
          Sleep(50);
        end;
        1: Break;
        else
        begin
          fBB.Reboot;
          fBB.Close;
        end;
      end;
    end;
  except
    // Log if desired
  end;
    Inc(attempts);
  until (fBB.id = 1) or (attempts >= MaxAttempts);

  if fBB.id <> 1 then
  begin
    TConsole.WriteLn('Unable to detect device', ccRed);
    Exit;
  end;

  try
    fBB.Ping0;

    // Get device info and validate
    tmp := fBB.GetVar(2, 2000);
    if Length(tmp) < SizeOf(TBRMetrics) then
    begin
      TConsole.WriteLn('Invalid device info received', ccRed);
      Exit(5);
    end;

    {$PUSH}
    {$R-}
    info := @tmp[4];
    {$POP}

    FmodelID := info^.modelID;

    // Combined validation: signed loader and address match
    if not isSignedLoader(tmp) then
    begin
      TConsole.WriteLn(Format('No valid signed loader found for model %.8X', [modelID]), ccRed);
      Exit(1);
    end;

    // Only check address if we have enough data (removed redundant model check)
    if (Length(tmp) >= 12) and (PDword(@tmp[8])^ <> IDtoADDR(modelId)) then
    begin
      TConsole.WriteLn(Format('Wrong loader for model %.8X', [modelID]), ccRed);
      Exit(2);
    end;

    if not fBB.SetMode(1) then
    begin
      fBB.Reboot;
      Exit(3);
    end;

    if fBB.PasswordInfo then
    begin
      fBB.SwitchChannel;
      fBB.GetMetrics;

      // Load and run loader
      SendAndRunLoader(tmp, runLoaderDelay);

      // Wait for loader mode ($8001)
      if not WaitForLoaderMode(MaxPostRunAttempts * 50) then
      begin
        TConsole.WriteLn('Timeout waiting for loader to start', ccRed);
        Exit(4);
      end;

      // Initialize loader interface
      if InitializeLoaderInterface then
      begin
        Result := 0;
        RebootPhone;

        // Update loaders.ini
        try
          Ini := TIniFile.Create('loaders.ini');
          try
            Ini.WriteString(ldr, IntToHex(modelId, 8), 'true');
            Ini.WriteString(IntToHex(modelId, 8), ldr, 'true');
          finally
            Ini.Free;
          end;
        except
          on E: Exception do
            TConsole.WriteLn('Warning: Could not update loaders.ini: ' + E.Message, ccYellow);
        end;
      end;
    end;
  except
    on E: Exception do
    begin
      Result := 100;
      TConsole.WriteLn('Unexpected error in probeLoader: ' + E.Message, ccRed);
    end;
  end;

  // Cleanup - only close, don't free fBB here (reuse for next probe)
  if Assigned(fBB) then
    fBB.Close;
  SafeFreeLoader(fBBLdr);
  Sleep(500);
end;

procedure TRamLoader.ProbeLoaders;
var
  UniqueLoaders: TStringList;
  SectionValues: TStringList;
  ValuePart: string;
  EqualPos: integer;
  k, attempts, i: integer;
  ldr: string;
  successful: boolean;
begin
  if not Assigned(LoaderMap) then
  begin
    TConsole.WriteLn('LoaderMap not initialized', ccRed);
    Exit;
  end;

  SectionValues := TStringList.Create;
  UniqueLoaders := TStringList.Create;
  try
    UniqueLoaders.Sorted := True;
    UniqueLoaders.Duplicates := dupIgnore;

    LoaderMap.ReadSectionValues('Loaders', SectionValues);

    // Extract unique loader names
    for i := 0 to SectionValues.Count - 1 do
    begin
      EqualPos := Pos('=', SectionValues[i]);
      if EqualPos > 0 then
      begin
        ValuePart := Copy(SectionValues[i], EqualPos + 1, MaxInt);
        UniqueLoaders.Add(ValuePart);
      end;
    end;

    // Probe each unique loader
    for ldr in UniqueLoaders do
    begin
      TConsole.WriteLn('Probing: ' + ldr);
      successful := False;
      attempts := 0;

      while (attempts < 20) and not successful do
      begin
        try
          k := probeLoader(ldr);
          TConsole.WriteLn(Format('probeLoader = %d', [k]));

          // Determine if we should continue or stop
          case k of
            0: begin
              successful := True;
              Break;
            end;  // Success
            1, 2: Break;  // Wrong/invalid loader, try next
            100: Break;  // Unexpected error, try next
            else
            begin   // Retry for other errors
              Inc(attempts);
              if attempts < 20 then Sleep(100);
            end;
          end;
        except
          on E: Exception do
          begin
            TConsole.WriteLn(Format('Error in probeLoader attempt %d: %s', [attempts, E.Message]), ccYellow);
            Inc(attempts);
            if attempts < 20 then Sleep(100);
          end;
        end;
      end;
    end;

  finally
    SectionValues.Free;
    UniqueLoaders.Free;
    // Clean up fBB after all probes are complete
    SafeCloseAndFree(fBB);
  end;
end;

function TRamLoader.IsValidSignature(const Data: TBytes): boolean;
var
  i: integer;
begin
  Result := False;
  if Length(Data) < $90 then // Minimum size check
    Exit;

  for i := 1 to $80 do
    if Data[Length(Data) - (16 + i)] <> $FF then
    begin
      Result := True;
      Break;
    end;
end;

function TRamLoader.isSignedLoader(const Data: TBytes): boolean;
var
  x: longword;
begin
  Result := False;

  if Length(Data) < 10240 then
    Exit;

  if (Length(Data) < 8) or (PDWord(@Data[4])^ <> $D7D32D1F) then
    Exit;

  x := Length(Data) - 8;
  if (x >= Length(Data)) or (PDWord(@Data[x])^ <> $D7C82D1F) then
    Exit;

  if IsValidSignature(Data) then
    Result := True;
end;

function TRamLoader.WaitForLoaderMode(timeoutMs: integer): boolean;
var
  attempts: integer;
begin
  Result := False;
  attempts := 0;
  while attempts * 50 < timeoutMs do
  begin
    try
      if not Assigned(fBB) then
        fBB := TBBUSB.Create;

      fBB.Open([$8001]);
      if (fBB.id = $8001) then
      begin
        Result := True;
        Exit;
      end;
    except
      // Ignore connection errors during waiting
    end;

    try
      fBB.Close;
    except
      // Ignore close errors
    end;
    Sleep(50);
    Inc(attempts);
  end;
end;

var
  ploader: IProgressIndicator;
  spinner: IProgressIndicator;

procedure lcb(i, s: integer);
begin
  if Assigned(ploader) then
    ploader.Update(i);
end;

procedure TRamLoader.SendAndRunLoader(const Data: TBytes; runDelay: integer);
var
  loadAddr: longword;
begin
  if Length(Data) < 12 then
    raise Exception.Create('Loader data is too short');

  Move(Data[8], loadAddr, SizeOf(loadAddr));

  TConsole.WriteLn(Format('Loader start address: 0x%.8x', [int64(loadAddr)]));
  TConsole.WriteLn('Sending loader to device...');

  try
    ploader := CreateProgressBar(Length(Data), 40);
    ploader.Start;
    if loadAddr = $80100000 then
      fBB.SendLoader(loadAddr, Data, 260, @lcb)   // OMAP 44xx
    else
      fBB.SendLoader(loadAddr, Data, 2024, @lcb); // Qualcomm
    ploader.Stop;
  except
    on E: Exception do
    begin
      if Assigned(ploader) then
        ploader.Stop;
      raise Exception.Create('Failed to send loader: ' + E.Message);
    end;
  end;

  Sleep(50);
  TConsole.WriteLn('Running loader...');
  fBB.RunLoader(loadAddr);
  Sleep(runDelay);

  fBB.Close;
end;

function TRamLoader.InitializeLoaderInterface: boolean;
begin
  Result := False;
  try
    if not Assigned(fBB) then
      fBB := TBBUSB.Create;

    fBB.Open([$8001]);
    // Reopen after switching to loader mode
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error reopening device in loader mode: ' + E.Message, ccRed);
      Exit(False);
    end;
  end;

  TConsole.WriteLn('Switching to Mode(2)...');
  if not fBB.SetMode(2) then
  begin
    TConsole.WriteLn('Failed to set Mode(2)', ccRed);
    Exit(False);
  end;

  TConsole.WriteLn('Getting Password Info...');
  if not fBB.PasswordInfo then
  begin
    TConsole.WriteLn('Failed to get password info', ccRed);
    Exit(False);
  end;

  SafeFreeLoader(fBBLdr);
  fBBLdr := TBBLoader.Create(fBB);

  TConsole.WriteLn('Retrieving Bugdisp log...');
  fBBLdr.BugdispLog;

  TConsole.WriteLn('Retrieving Flash region info...');
  fBBLdr.FlashRegionsInfo;
  Result := True;
end;

function TRamLoader.IDtoADDR(const ID: cardinal): cardinal;
var
  xID: cardinal;
begin
  xID := id and $FFFF;
  if id = $B600240A then Exit($0DD00000);

  case xID of
    $080a, $240a, $270a, $2a0a, $2e0a, $2e07: Result := $80200000;
    $1a06, $2307, $2607, $260a: Result := $80100000;
    $2c0a: Result := $0DD00000;
    else
      Result := $FFFFFFFF;
  end;
end;

function TRamLoader.isValidLoader(const Data: TBytes): boolean;
begin
  Result := False;
  if isSignedLoader(Data) and (Length(Data) >= 12) then
    if PDword(@Data[8])^ = IDtoADDR(FModelID) then
      Result := True;
end;

function TRamLoader.ConnectToBB(const runLoaderDelay: integer = 1000; verbose: boolean = False): boolean;
const
  MaxAttempts = 200;         // ~10 seconds
  MaxPostRunAttempts = 600;  // ~30 seconds
var
  tmp: TBytes;
  attempts, l: integer;
  devInfo: TFullDeviceInfo;
  info: PBRMetrics;
  ids: specialize TArray<word>;
begin
  Result := False;

  if not Assigned(fBB) then
    fBB := TBBUSB.Create;

  attempts := 0;
  repeat
  try
    ids := fBB.GetProductIDs($0FCA);
    l := length(ids);
    if l = 0 then
    begin
      Sleep(100);
      Inc(attempts);
    end;
    if attempts >= MaxPostRunAttempts then
      Exit(False);
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Error getting product IDs: ' + E.Message, ccYellow);
      Sleep(100);
      Inc(attempts);
      if attempts >= MaxPostRunAttempts then
        Exit(False);
    end;
  end;
  until (l <> 0);

  if (Length(ids) > 0) and (ids[0] <> 1) and (ids[0] <> $8001) then
  begin
    try
      fBB.Open([]);
      fBB.Reboot;
      fBB.Close;
      Sleep(2000);
    except
      // Ignore reboot errors
    end;
  end;

  // Wait for device in mode 1
  attempts := 0;
  if Assigned(spinner) then
    spinner.Start;

  repeat
  try
    fBB.Open([1, $8001]);
    case fBB.id of
      0:
      begin
        fBB.Close;
        Sleep(50);
      end;
      1:
        Break;
      else
      begin
        fBB.Reboot;
        fBB.Close;
      end;
    end;
  except
    // Log if desired
  end;
    if Assigned(spinner) then
      spinner.Update(0);
    Inc(attempts);
  until (fBB.id = 1) or (attempts >= MaxAttempts);

  if fBB.id <> 1 then
  begin
    TConsole.WriteLn('Unable to detect device', ccRed);
    Exit;
  end;

  try
    fBB.Ping0;

    // Set mode 1
    FBRomInfo := fBB.GetVar(2, 2000);
    if Length(FBRomInfo) < SizeOf(TBRMetrics) then
    begin
      TConsole.WriteLn('Invalid device info received', ccRed);
      Exit;
    end;

    {$PUSH}
    {$R-}
    info := @FBRomInfo[4];
    {$POP}

    if not fBB.SetMode(1) then
      Exit;

    if Assigned(spinner) then
      spinner.Stop;

    TConsole.WriteLn('BlackBerry device found');
    if verbose then
    begin
      TryGetDeviceInfoByID(info^.modelID, devInfo);
      TConsole.WriteLn(Format('%s %s (%.8x)', [devInfo.FullName, devInfo.ModelCode, int64(info^.modelID)]));
      TConsole.WriteLn('Build User: ' + ReadCString(info^.BuildUser));
      TConsole.WriteLn('Build Date: ' + ReadCString(info^.BuildDate));
      TConsole.WriteLn('Build Time: ' + ReadCString(info^.BuildTime));
      TConsole.WriteLn('Hardware OS ID: 0x' + IntToHex(info^.HWOSId, 8));
      TConsole.WriteLn(Format('BR ID: %.8x', [int64(info^.BRId)]));
    end;
    if not fBB.PasswordInfo then
      Exit(False);

    fBB.SwitchChannel;
    fBB.GetMetrics;
    if runLoaderDelay < 0 then
    begin
      fBB.Nuke;
      Result := True;
    end
    else
    begin

      FModelID := info^.modelID;

      if not LoadLoader(FModelID, tmp) then
      begin
        TConsole.WriteLn(Format('No valid loader found for %.8x', [qword(FModelID)]));
        Exit(False);
      end;

      // Load and run loader
      SendAndRunLoader(tmp, runLoaderDelay);

      // Wait for loader mode ($8001)
      if not WaitForLoaderMode(MaxPostRunAttempts * 50) then
      begin
        TConsole.WriteLn('Timeout waiting for loader to start', ccRed);
        Exit;
      end;

      // Initialize loader interface
      Result := InitializeLoaderInterface;

    end;
  except
    on E: Exception do
    begin
      TConsole.WriteLn('Unexpected error: ' + E.Message, ccRed);
      Result := False;
    end;
  end;
end;

procedure TRamLoader.RebootPhone;
begin
  // Reboot device
  if Assigned(fBBLdr) then
  begin
    try
      fBBLdr.Reboot;
    except
      // Ignore reboot errors
    end;
    SafeFreeLoader(fBBLdr);
  end;

  if Assigned(fBB) then
  begin
    try
      fBB.Reboot;
      fBB.Close;
    except
      // Ignore reboot/close errors
    end;
    SafeCloseAndFree(fBB);
  end;

  // Cleanup
  fBB := TBBUSB.Create;
  try
    fBB.Open([1, $8001]);
  except
    // Ignore connection errors
  end;
  SafeCloseAndFree(fBB);
end;

function TRamLoader.FlashFile(fName: string; ver: byte = 2): integer;
var
  fPayload: TStream;
  Buff: TBytes;
  s: int64;
  cb, bs, TotalBlocks: longword;
  progress: IProgressIndicator;
  iFiles: TStringList;
  isMFCQ: boolean;
begin
  if not FileExists(fName) then
  begin
    TConsole.WriteLn('File not found: ' + fName, ccRed);
    Exit(-1);
  end;

  // Open main stream
  fPayload := nil;
  try
    fPayload := TFileStream.Create(fName, fmOpenRead);

    // Check for MFCQ format
    isMFCQ := fPayload.ReadDWord = $7163666D;
    fPayload.Position := 0;

    if not isMFCQ then
    begin
      FreeAndNil(fPayload);
      fPayload := TMemoryStream.Create;
      iFiles := TStringList.Create;
      try
        iFiles.Add(fName);
        TConsole.WriteLn('Making QCFM');
        _packMFCQ(fPayload, iFiles, nil, ver, ver = 2);
      finally
        iFiles.Free;
      end;
    end;

    // Position to signature
    s := fPayload.Size;
    if isMFCQ and (s > 560) then
    begin
      fPayload.Position := s - 560;
      if fPayload.ReadDWord = $48584e51 then
      begin
        fPayload.Position := s - 560;
        if fPayload.Read(dummy_signature[0], 560) <> 560 then
          TConsole.WriteLn('Warning: Could not read complete signature', ccYellow);
        s := s - 560;
      end;
    end;

    fPayload.Position := 0;

    if not Assigned(fBBLdr) then
    begin
      TConsole.WriteLn('Loader interface not initialized', ccRed);
      Exit(-2);
    end;

    if (fModelID and $FFFF) = $2c0a then
      fBBLdr.PreFlash($40)
    else
      fBBLdr.PreFlash($15);

    // Initialize transmission
    SetLength(Buff, MAX_FLASH_BLOCK);
    TotalBlocks := s div MAX_FLASH_BLOCK + Ord(s mod MAX_FLASH_BLOCK > 0);
    cb := 0;

    progress := CreateProgressBar(TotalBlocks, 40);
    progress.Start;

    try
      while fPayload.Position < s do
      begin
        bs := Min(s - fPayload.Position, MAX_FLASH_BLOCK - 8);
        if bs < MAX_FLASH_BLOCK - 8 then
          SetLength(Buff, bs + 8);

        if fPayload.Read(Buff[8], bs) <> bs then
        begin
          TConsole.WriteLn('Error reading file data', ccRed);
          Break;
        end;

        if not fBBLdr.SendBlock(Buff) then
        begin
          TConsole.WriteLn('Flash error', ccRed);
          progress.Stop;
          FreeAndNil(fPayload);
          Exit(-3);
        end;

        Inc(PDWord(@Buff[0])^);
        Inc(cb);
        progress.Update(cb);
      end;
    finally
      progress.Stop;
    end;

    // Send signature
    TConsole.WriteLn('Send signature');
    SetLength(Buff, 560 + 2);
    Move(dummy_signature[0], Buff[2], 560);
    PWord(@Buff[0])^ := word(560);

    if not fBBLdr.SendSignature(Buff) then
      TConsole.WriteLn('Signature send error', ccRed);
    Sleep(1000);
  finally
    if Assigned(fPayload) then
      fPayload.Free;
  end;

  if Assigned(fBBLdr) then
    fBBLdr.Complete;
  TConsole.WriteLn('Done');
  Result := 0;
end;


var
  Dir: string;

initialization
try
  Dir := GetExeDirectory;
  if FileExistsUTF8(Dir + 'bb10mt.ini') then
    LoaderMap := TMemIniFile.Create(Dir + 'bb10mt.ini')
  else
    TConsole.WriteLn('Warning: bb10mt.ini not found', ccYellow);
except
  on E: Exception do
    TConsole.WriteLn('Warning: Could not load bb10mt.ini: ' + E.Message, ccYellow);
end;

try
  if FileExistsUTF8(Dir + 'loaders.dat') then
    Loaders := TMyArcReader.Create(Dir + 'loaders.dat')
  else
    TConsole.WriteLn('Warning: loaders.dat not found', ccYellow);
except
  on E: Exception do
    TConsole.WriteLn('Warning: Could not load loaders.dat: ' + E.Message, ccYellow);
end;

finalization
  if Assigned(LoaderMap) then
    FreeAndNil(LoaderMap);
  if Assigned(Loaders) then
    FreeAndNil(Loaders);

end.
