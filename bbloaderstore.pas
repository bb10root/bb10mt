unit bbloaderstore;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, IniFiles, FileUtil, LazFileUtils, uArchive, uMisc, bbdevicedb, CLI.Console;

type
  TBBLoaderStore = class
  private
    FLdrDir: string;
    FLoaderMap: TMemIniFile;
    FLoadersArc: TMyArcReader;

    function IsValidSignature(const Data: TBytes): boolean;
    function IsSignedLoader(const Data: TBytes): boolean;
    function FindLoaderResource(const ID: string): string;
    function ModelToRes(ModelID: cardinal): string;
  public
    constructor Create(const LdrDir: string);
    destructor Destroy; override;

    function IsValidLoader(const Data: TBytes; ModelID: cardinal): boolean;
    function ForceLoader(const fName: string; var Data: TBytes; ModelID: cardinal): boolean;
    function LoadLoader(ModelID: cardinal; var Data: TBytes): boolean;
    procedure GetUniqueLoaderList(List: TStringList);
    procedure UpdateLoaderMap(const LdrName: string; ModelID: cardinal);

    property LoaderDirectory: string read FLdrDir;
  end;

implementation

constructor TBBLoaderStore.Create(const LdrDir: string);
var
  BaseDir: string;
begin
  inherited Create;
  FLdrDir := LdrDir;
  BaseDir := GetExeDirectory;

  if FileExistsUTF8(BaseDir + 'bb10mt.ini') then
    FLoaderMap := TMemIniFile.Create(BaseDir + 'bb10mt.ini')
  else
    FLoaderMap := nil;

  if FileExistsUTF8(BaseDir + 'loaders.dat') then
    FLoadersArc := TMyArcReader.Create(BaseDir + 'loaders.dat')
  else
    FLoadersArc := nil;
end;

destructor TBBLoaderStore.Destroy;
begin
  if Assigned(FLoaderMap) then FreeAndNil(FLoaderMap);
  if Assigned(FLoadersArc) then FreeAndNil(FLoadersArc);
  inherited Destroy;
end;

function TBBLoaderStore.IsValidSignature(const Data: TBytes): boolean;
var
  i: integer;
begin
  Result := False;
  if Length(Data) < $90 then Exit;

  for i := 1 to $80 do
    if Data[Length(Data) - (16 + i)] <> $FF then
    begin
      Result := True;
      Break;
    end;
end;

function TBBLoaderStore.IsSignedLoader(const Data: TBytes): boolean;
var
  x: longword;
begin
  Result := False;
  if Length(Data) < 10240 then Exit;
  if (Length(Data) < 8) or (PDWord(@Data[4])^ <> $D7D32D1F) then Exit;

  x := Length(Data) - 8;
  if (x >= Length(Data)) or (PDWord(@Data[x])^ <> $D7C82D1F) then Exit;

  Result := IsValidSignature(Data);
end;

function TBBLoaderStore.IsValidLoader(const Data: TBytes; ModelID: cardinal): boolean;
begin
  Exit(True);
  Result := False;
  if IsSignedLoader(Data) and (Length(Data) >= 12) then
    if PDWord(@Data[8])^ = IDtoADDR(ModelID) then
      Result := True;
end;

function TBBLoaderStore.FindLoaderResource(const ID: string): string;
begin
  if Assigned(FLoaderMap) then
    Result := FLoaderMap.ReadString('Loaders', ID, '')
  else
    Result := '';
end;

function TBBLoaderStore.ModelToRes(ModelID: cardinal): string;
begin
  Result := FindLoaderResource(Format('%.8x', [int64(ModelID)]));
end;

function TBBLoaderStore.ForceLoader(const fName: string; var Data: TBytes; ModelID: cardinal): boolean;
var
  iFile: TFileStream;
  s1: int64;
begin
  Result := False;
  if not FileExists(fName) then Exit;

  try
    iFile := TFileStream.Create(fName, fmOpenRead or fmShareDenyWrite);
    try
      s1 := iFile.Size;
      if s1 <= 0 then Exit;

      SetLength(Data, s1);
      iFile.ReadBuffer(Data[0], s1);
    finally
      iFile.Free;
    end;

    if IsValidLoader(Data, ModelID) then
    begin
      TConsole.WriteLn(Format('loader: %s ', [fName]));
      Result := True;
    end
    else
      SetLength(Data, 0);
  except
    on E: Exception do
    begin
      TConsole.WriteLn(Format('Error loading file %s: %s', [fName, E.Message]), ccRed);
      SetLength(Data, 0);
    end;
  end;
end;

function TBBLoaderStore.LoadLoader(ModelID: cardinal; var Data: TBytes): boolean;
var
  fName, resName: string;
  ldrList: TStringList;
  iFile: TFileStream;
  s1: int64;
begin
  Result := False;

  ldrList := FindAllFiles(FLdrDir, Format('loader_%.8X*.bin', [int64(ModelID)]), False);
  if Assigned(ldrList) then
  try
    for fName in ldrList do
    begin
      if not FileExists(fName) then Continue;

      try
        iFile := TFileStream.Create(fName, fmOpenRead or fmShareDenyWrite);
        try
          s1 := iFile.Size;
          if s1 <= 0 then Continue;

          SetLength(Data, s1);
          iFile.ReadBuffer(Data[0], s1);
        finally
          iFile.Free;
        end;

        if IsValidLoader(Data, ModelID) then
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

  resName := ModelToRes(ModelID);
  if (resName <> '') and Assigned(FLoadersArc) and FLoadersArc.FileExists(resName) then
  begin
    try
      if not FLoadersArc.ExtractToBytes(resName, Data) then
      begin
        TConsole.WriteLn('Failed to decompress resource: ' + resName, ccRed);
        Exit(False);
      end;

      if IsValidLoader(Data, ModelID) then
      begin
        TConsole.WriteLn(Format('loader: %s ', [resName]));
        Result := True;
      end
      else
        SetLength(Data, 0);
    except
      on E: Exception do
      begin
        TConsole.WriteLn(Format('Error loading resource %s: %s', [resName, E.Message]), ccRed);
        SetLength(Data, 0);
      end;
    end;
  end;
end;

procedure TBBLoaderStore.GetUniqueLoaderList(List: TStringList);
var
  SectionValues: TStringList;
  ValuePart: string;
  EqualPos, i: integer;
begin
  if not Assigned(FLoaderMap) or not Assigned(List) then Exit;

  SectionValues := TStringList.Create;
  try
    FLoaderMap.ReadSectionValues('Loaders', SectionValues);
    for i := 0 to SectionValues.Count - 1 do
    begin
      EqualPos := Pos('=', SectionValues[i]);
      if EqualPos > 0 then
      begin
        ValuePart := Copy(SectionValues[i], EqualPos + 1, MaxInt);
        List.Add(ValuePart);
      end;
    end;
  finally
    SectionValues.Free;
  end;
end;

procedure TBBLoaderStore.UpdateLoaderMap(const LdrName: string; ModelID: cardinal);
var
  Ini: TIniFile;
begin
  try
    Ini := TIniFile.Create('loaders.ini');
    try
      Ini.WriteString(LdrName, IntToHex(ModelID, 8), 'true');
      Ini.WriteString(IntToHex(ModelID, 8), LdrName, 'true');
    finally
      Ini.Free;
    end;
  except
    on E: Exception do
      TConsole.WriteLn('Warning: Could not update loaders.ini: ' + E.Message, ccYellow);
  end;
end;

end.
