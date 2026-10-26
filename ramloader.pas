unit RamLoader;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, bbconst, bbdevice, bbclient,
  bbdevicedb, bbloaderstore, bbflasher;

type
  TRamLoader = class
  private
    fClient: TBBClient;
    fStore: TBBLoaderStore;
    FModelID: cardinal;
    FBRomInfo: TBytes;

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
    procedure ProbeLoaders;

    property ModelID: cardinal read FModelID;
    property Client: TBBClient read fClient;
    property Store: TBBLoaderStore read fStore;
    property BootromInfo: TBytes read FBRomInfo;
  end;

implementation

uses
  uInfo, CLI.Interfaces, CLI.Progress, CLI.Console, uMisc;

var
  ploader: IProgressIndicator;

procedure lcb(i, s: integer);
begin
  if Assigned(ploader) then
    ploader.Update(i);
end;

{ TRamLoader }

constructor TRamLoader.Create(Dir: string = '');
var
  LdrDir: string;
begin
  inherited Create;
  fClient := TBBClient.Create;
  if Dir = '' then
    LdrDir := GetExeDirectory + 'loaders'
  else
    LdrDir := Dir;
  fStore := TBBLoaderStore.Create(LdrDir);
  FModelID := 0;
  SetLength(FBRomInfo, 0);
end;

destructor TRamLoader.Destroy;
begin
  SetLength(FBRomInfo, 0);
  FreeAndNil(fStore);
  FreeAndNil(fClient);
  inherited Destroy;
end;

function TRamLoader.WaitForLoaderMode(timeoutMs: integer): boolean;
begin
  Result := fClient.Connect([$8001], timeoutMs);
end;

procedure TRamLoader.SendAndRunLoader(const Data: TBytes; runDelay: integer);
var
  loadAddr: longword;
  chunkSize: integer;
begin
  if Length(Data) < 12 then
    raise Exception.Create('Loader data is too short');

  Move(Data[8], loadAddr, SizeOf(loadAddr));

  TConsole.WriteLn(Format('Loader start address: 0x%.8x', [int64(loadAddr)]));
  TConsole.WriteLn('Sending loader to device...');

  try
    ploader := CreateProgressBar(Length(Data), 40);
    if Assigned(ploader) then ploader.Start;

    if (loadAddr = $80100000) then
      chunkSize := 260
    else if (loadAddr = $B8000000) then
      chunkSize := 144
    else
      chunkSize := 2024;

    fClient.Device.SendLoader(loadAddr, Data, chunkSize, @lcb);

    if Assigned(ploader) then ploader.Stop;
  except
    on E: Exception do
    begin
      if Assigned(ploader) then ploader.Stop;
      raise Exception.Create('Failed to send loader: ' + E.Message);
    end;
  end;

  Sleep(50);
  TConsole.WriteLn('Running loader...');
  fClient.Device.RunLoader(loadAddr);
  Sleep(runDelay);

  fClient.Disconnect;
end;

function TRamLoader.InitializeLoaderInterface: boolean;
begin
  Result := False;
  if not fClient.Connect([$8001]) then
  begin
    TConsole.WriteLn('Error reopening device in loader mode', ccRed);
    Exit(False);
  end;

  TConsole.WriteLn('Switching to Mode(2)...');
  if not fClient.Device.SetMode(2) then
  begin
    TConsole.WriteLn('Failed to set Mode(2)', ccRed);
    Exit(False);
  end;

  TConsole.WriteLn('Getting Password Info...');
  if not fClient.Device.PasswordInfo then
  begin
    TConsole.WriteLn('Failed to get password info', ccRed);
    Exit(False);
  end;

  TConsole.WriteLn('Retrieving Bugdisp log...');
  fClient.Loader.BugdispLog;

  TConsole.WriteLn('Retrieving Flash region info...');
  fClient.Loader.FlashRegionsInfo;
  Result := True;
end;

function TRamLoader.probeLoader(const ldr: string): integer;
const
  MaxPostRunAttempts = 600;
var
  romInfoBytes, ldrData: TBytes;
  info: PBRMetrics;
  runLoaderDelay: integer = 1000;
begin
  Result := -1;
  TConsole.WriteLn('Connecting to BootROM...');

  if not fClient.Connect([1, $8001], 5000) then
  begin
    TConsole.WriteLn('Unable to detect device', ccRed);
    Exit;
  end;

  try
    fClient.Device.Ping0;

    romInfoBytes := fClient.Device.GetVar(2, 2000);
    if Length(romInfoBytes) < SizeOf(TBRMetrics) then
    begin
      TConsole.WriteLn('Invalid device info received', ccRed);
      Exit(5);
    end;

    {$PUSH}
    {$R-}
    {$Q-}
    info := @romInfoBytes[4];
    {$POP}

    FModelID := info^.modelID;

    if not fStore.ForceLoader(fStore.LoaderDirectory + DirectorySeparator + ldr, ldrData, FModelID) then
    begin
      TConsole.WriteLn(Format('No valid signed loader file "%s" for model %.8X', [ldr, FModelID]), ccRed);
      Exit(1);
    end;

    if (Length(ldrData) >= 12) and (PDWord(@ldrData[8])^ <> IDtoADDR(FModelID)) then
    begin
      TConsole.WriteLn(Format('Wrong loader address for model %.8X', [FModelID]), ccRed);
      Exit(2);
    end;

    if not fClient.Device.SetMode(1) then
    begin
      fClient.Device.Reboot;
      Exit(3);
    end;

    if fClient.Device.PasswordInfo then
    begin
      fClient.Device.SwitchChannel;
      fClient.Device.GetMetrics;

      SendAndRunLoader(ldrData, runLoaderDelay);

      if not WaitForLoaderMode(MaxPostRunAttempts * 50) then
      begin
        TConsole.WriteLn('Timeout waiting for loader to start', ccRed);
        Exit(4);
      end;

      if InitializeLoaderInterface then
      begin
        Result := 0;
        RebootPhone;
        fStore.UpdateLoaderMap(ldr, FModelID);
      end;
    end;
  except
    on E: Exception do
    begin
      Result := 100;
      TConsole.WriteLn('Unexpected error in probeLoader: ' + E.Message, ccRed);
    end;
  end;

  fClient.Disconnect;
  Sleep(500);
end;

procedure TRamLoader.ProbeLoaders;
var
  UniqueLoaders: TStringList;
  attempts, k: integer;
  ldr: string;
  successful: boolean;
begin
  UniqueLoaders := TStringList.Create;
  try
    UniqueLoaders.Sorted := True;
    UniqueLoaders.Duplicates := dupIgnore;

    fStore.GetUniqueLoaderList(UniqueLoaders);

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

          case k of
            0: begin
              successful := True;
              Break;
            end;
            1, 2, 100: Break;
            else
            begin
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
    UniqueLoaders.Free;
    fClient.Disconnect;
  end;
end;

function TRamLoader.ConnectToBB(const runLoaderDelay: integer = 1000; verbose: boolean = False): boolean;
const
  MaxPostRunAttempts = 600;
var
  tmp: TBytes;
  devInfo: TFullDeviceInfo;
  info: PBRMetrics;
begin
  Result := False;

  if not fClient.Connect([], 10000) then
  begin
    TConsole.WriteLn('Unable to detect device', ccRed);
    Exit(False);
  end;

  if fClient.Device.ID <> 1 then
  begin
    fClient.RebootAndReconnect([1], 60000);
  end;

  try
    fClient.Device.Ping0;

    FBRomInfo := fClient.Device.GetVar(2, 2000);
    if Length(FBRomInfo) < SizeOf(TBRMetrics) then
    begin
      TConsole.WriteLn('Invalid device info received', ccRed);
      Exit(False);
    end;

    {$PUSH}
    {$R-}
    {$Q-}
    info := @FBRomInfo[4];
    {$POP}

    if not fClient.Device.SetMode(1) then Exit(False);

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

    if not fClient.Device.PasswordInfo then Exit(False);

    fClient.Device.SwitchChannel;
    fClient.Device.GetMetrics;

    if runLoaderDelay < 0 then
    begin
      fClient.Device.Nuke;
      Result := True;
    end
    else
    begin
      FModelID := info^.modelID;

      if not fStore.LoadLoader(FModelID, tmp) then
      begin
        TConsole.WriteLn(Format('No valid loader found for %.8x', [qword(FModelID)]));
        Exit(False);
      end;

      SendAndRunLoader(tmp, runLoaderDelay);

      if not WaitForLoaderMode(MaxPostRunAttempts * 50) then
      begin
        TConsole.WriteLn('Timeout waiting for loader to start', ccRed);
        Exit(False);
      end;

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
  fClient.RebootAndReconnect([1, $8001], 2000, 5000);
end;

function TRamLoader.FlashFile(fName: string; ver: byte = 2): integer;
var
  Flasher: TBBFlasher;
begin
  if not fClient.IsConnected then
  begin
    TConsole.WriteLn('Loader interface not initialized', ccRed);
    Exit(-2);
  end;

  Flasher := TBBFlasher.Create(fClient.Loader);
  try
    Result := Flasher.FlashFile(fName, FModelID, ver);
  finally
    Flasher.Free;
  end;
end;

end.
