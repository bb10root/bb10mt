unit uBarUtils;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils;

procedure UpdateHashes(const aBaseDir: string);
procedure UpdateIds(const aBaseDir: string);
procedure CreateBar(const aBaseDir: string; const Name: string);

{$IFDEF LINUX}
function InstallUnpackedBar(const bar: string; const mountPoint: string): integer;
{$ENDIF}

implementation

uses
  StrUtils, LazFileUtils, Types, FileUtil,
  fpjson,
  mormot.crypt.core,
  uCrypto,
  DOM, XMLRead
  {$IFDEF LINUX}
  , BaseUnix, Unix
  {$ENDIF}
  ;

const
  metafile = 'META-INF' + DirectorySeparator + 'MANIFEST.MF';

function CalcSha512(const aFileName: string): string;
var
  FS: TFileStream;
begin
  Result := '';
  FS := TFileStream.Create(aFileName, fmOpenRead or fmShareDenyWrite);
  try
    Result := Base64UrlEncode(SHA512OfStreamHex(FS));
  finally
    FS.Free;
  end;
end;

function GenID(const Seed: rawbytestring): string;
begin
  Result := Base64UrlEncode(Sha1(Seed));
end;

function GetRandomId: string;
var
  G: TGUID;
  Buf: rawbytestring;
begin
  if CreateGUID(G) <> S_OK then
    Exit('');

  SetLength(Buf, SizeOf(TGUID));
  Move(G, Buf[1], SizeOf(TGUID));
  Result := GenID(Buf);
end;

procedure UpdateIds(const aBaseDir: string);
const
  Keys: array[0..4] of string = (
    'Package-Author-Id',
    'Package-Id',
    'Package-Version-Id',
    'Application-Id',
    'Application-Version-Id'
    );
  Prefixes: array[0..4] of string = ('A', 'B', 'C', 'D', 'E');
var
  sl: TStringList;
  metaPath: string;
  i, idx, sepPos: integer;
  keyName: string;
begin
  metaPath := IncludeTrailingPathDelimiter(aBaseDir) + metafile;
  if not FileExists(metaPath) then Exit;

  sl := TStringList.Create;
  try
    sl.LoadFromFile(metaPath);

    for i := 0 to sl.Count - 1 do
    begin
      sepPos := Pos(':', sl[i]);
      if sepPos > 0 then
      begin
        keyName := Trim(Copy(sl[i], 1, sepPos - 1));

        for idx := Low(Keys) to High(Keys) do
        begin
          if SameText(keyName, Keys[idx]) then
          begin
            sl[i] := Format('%s: andr%s%s', [Keys[idx], Prefixes[idx], GetRandomId]);
            Break;
          end;
        end;
      end;
    end;

    sl.SaveToFile(metaPath);
  finally
    sl.Free;
  end;
end;

function GenerateManifestHeader(const Name: string): string;
begin
  Result := Format('Archive-Manifest-Version: 1.5' + LineEnding +
    'Archive-Created-By: BlackBerry Data BAR Packager 1.11' +
    LineEnding + 'Package-Type: system-data' + LineEnding +
    'Package-Author: Research In Motion Limited' + LineEnding +
    'Package-Author-Id: andrA%s' + LineEnding + 'Package-Name: sys.data.%s' +
    LineEnding + 'Package-Id: andrB%s' + LineEnding + 'Package-Version: 1.0.0.0' +
    LineEnding + 'Package-Version-Id: andrC%s' + LineEnding +
    'Package-Architecture: armle-v7' + LineEnding + LineEnding +
    'System-Data-Type: os_data' + LineEnding +
    'System-Data-Requires-System: os/10.0.0.8' + LineEnding +
    'System-Data-Persistence: permanent' + LineEnding,
    [GetRandomId, Name, GetRandomId, GetRandomId]);
end;

function ManifestMain(const aFileName: string): string;
const
  SearchTag = 'Archive-Asset-';
var
  sl, acc: TStringList;
  i: integer;
begin
  Result := '';
  if not FileExists(aFileName) then Exit;

  sl := TStringList.Create;
  acc := TStringList.Create;
  try
    sl.LoadFromFile(aFileName);
    for i := 0 to sl.Count - 1 do
    begin
      if Pos(SearchTag, sl[i]) > 0 then
        Break;
      acc.Add(sl[i]);
    end;
    Result := acc.Text;
  finally
    sl.Free;
    acc.Free;
  end;
end;

function ParseManifest(const FileName: string): TJSONObject;
var
  Lines: TStringList;
  SectionArr: TJSONArray;
  SectionObj, AttrObj: TJSONObject;
  i, ColonPos: integer;
  sLine, Key, Value: string;
begin
  Result := TJSONObject.Create;
  SectionArr := TJSONArray.Create;
  Result.Add('sections', SectionArr);

  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(FileName);

    AttrObj := TJSONObject.Create;
    SectionObj := TJSONObject.Create(['_', AttrObj]);

    for i := 0 to Lines.Count - 1 do
    begin
      sLine := Trim(Lines[i]);
      if sLine = '' then
      begin
        if AttrObj.Count > 0 then
          SectionArr.Add(SectionObj)
        else
          SectionObj.Free;

        AttrObj := TJSONObject.Create;
        SectionObj := TJSONObject.Create(['_', AttrObj]);
      end
      else
      begin
        ColonPos := Pos(':', sLine);
        if ColonPos > 0 then
        begin
          Key := Trim(Copy(sLine, 1, ColonPos - 1));
          Value := Trim(Copy(sLine, ColonPos + 1, MaxInt));
          AttrObj.Add(Key, Value);
        end;
      end;
    end;

    if AttrObj.Count > 0 then
      SectionArr.Add(SectionObj)
    else
      SectionObj.Free;

  finally
    Lines.Free;
  end;
end;

function FindSectionWithAttrs(Sections: TJSONArray;
  const Attrs: array of string): TJSONObject;
var
  i, a: integer;
  Section, Inner: TJSONObject;
  Found: boolean;
begin
  for i := 0 to Sections.Count - 1 do
  begin
    Section := Sections.Objects[i];
    if Section = nil then Continue;

    Inner := Section.Objects['_'];
    if Inner = nil then Continue;

    Found := True;
    for a := Low(Attrs) to High(Attrs) do
    begin
      if Inner.Find(Attrs[a]) = nil then
      begin
        Found := False;
        Break;
      end;
    end;

    if Found then
      Exit(Inner);
  end;

  Result := nil;
end;

function GetAttr(const Obj: TJSONObject; const Name: string): string;
var
  Val: TJSONData;
begin
  if Obj = nil then Exit('');
  Val := Obj.Find(Name);
  if Assigned(Val) then
    Result := Val.AsString
  else
    Result := '';
end;

function GetPackageDName(Manifest: TJSONObject): string;
var
  Sections: TJSONArray;
  Attrs: TJSONObject;
  PackageName, PackageId: string;
begin
  Sections := Manifest.Arrays['sections'];
  if (Sections = nil) or (Sections.Count = 0) then
    raise Exception.Create('Manifest has no sections.');

  Attrs := FindSectionWithAttrs(Sections, ['Package-Name', 'Package-Id']);
  if Attrs = nil then
    raise Exception.Create('Package-Name and Package-Id not found in any section.');

  PackageName := GetAttr(Attrs, 'Package-Name');
  PackageId := GetAttr(Attrs, 'Package-Id');

  Result := Format('%s.%s', [PackageName, PackageId]);
end;

function ConvertManifestToApplications(ManifestJSON: TJSONObject;
  const Gid: integer; const Extras: string): string;
var
  OutputJSON: TJSONObject;
  Sections: TJSONArray;
  Attrs: TJSONObject;
  PackageName, PackageId, PackageVersion, PackageVersionId: string;
begin
  OutputJSON := TJSONObject.Create;
  try
    Sections := ManifestJSON.Arrays['sections'];
    if (Sections = nil) or (Sections.Count = 0) then
      raise Exception.Create('Manifest has no sections.');

    Attrs := FindSectionWithAttrs(Sections, ['Package-Name', 'Package-Id',
      'Package-Version', 'Package-Version-Id']);
    if Attrs = nil then
      raise Exception.Create('Required package fields not found.');

    PackageName := GetAttr(Attrs, 'Package-Name');
    PackageId := GetAttr(Attrs, 'Package-Id');
    PackageVersion := GetAttr(Attrs, 'Package-Version');
    PackageVersionId := GetAttr(Attrs, 'Package-Version-Id');

    OutputJSON.Add('Package-Id', PackageId);
    OutputJSON.Add('Package-Version', PackageVersion);
    OutputJSON.Add('Package-Version-Id', PackageVersionId);
    OutputJSON.Add('_', ManifestJSON.Clone);
    OutputJSON.Add('extras', Extras);
    OutputJSON.Add('gid', Gid);

    Result := Format('%s.%s:json:%s', [PackageName, PackageId, OutputJSON.AsJSON]);
  finally
    OutputJSON.Free;
  end;
end;

function ConvertManifestToRegisteredApp(Manifest: TJSONObject;
  const Gid: integer; const Extras: string): string;
var
  Sections: TJSONArray;
  Attrs: TJSONObject;
  PkgName, PkgId, PkgVersion: string;
begin
  Sections := Manifest.Arrays['sections'];
  if (Sections = nil) or (Sections.Count = 0) then
    raise Exception.Create('Manifest has no sections.');

  Attrs := FindSectionWithAttrs(Sections, ['Package-Name', 'Package-Id',
    'Package-Version']);
  if Attrs = nil then
    raise Exception.Create('Required fields not found.');

  PkgName := GetAttr(Attrs, 'Package-Name');
  PkgId := GetAttr(Attrs, 'Package-Id');
  PkgVersion := GetAttr(Attrs, 'Package-Version');

  Result := Format('%s.%s::%s,%s,,,%d,%s', [PkgName, PkgId, PkgId,
    PkgVersion, Gid, Extras]);
end;

function ConvertManifestToServices(Manifest: TJSONObject): TStringList;
const
  DEFAULT_TIMEOUT = '30';
var
  Sections: TJSONArray;
  Section, Attrs: TJSONObject;
  PkgName, PkgId: string;
  i: integer;
  ResultPairs: TStringList;
  ParamList, PathList: TStringList;
  JSONArr: TJSONArray;

  procedure ParseEntryPoint(const EPKey, EPExpr: string);
  var
    Timeout, Value, Key, JsonPart: string;
    j, sepPos: integer;
  begin
    if (EPKey = '') or (EPExpr = '') then Exit;

    Timeout := DEFAULT_TIMEOUT;
    ParamList.Clear;
    PathList.Clear;
    JSONArr.Clear;

    sepPos := Pos('[', EPExpr);
    if sepPos > 0 then
      ParamList.DelimitedText := Copy(EPExpr, sepPos + 1, Pos(']', EPExpr) - sepPos - 1)
    else
      Exit;

    ParamList.StrictDelimiter := True;
    ParamList.Delimiter := ' ';

    for j := 0 to ParamList.Count - 1 do
    begin
      Value := ParamList[j];
      if AnsiStartsText('timeout=', Value) then
        Timeout := Copy(Value, Length('timeout=') + 1, MaxInt)
      else if AnsiStartsText('path=', Value) then
      begin
        Value := Copy(Value, Length('path=') + 1, MaxInt);
        PathList.StrictDelimiter := True;
        PathList.Delimiter := ':';
        PathList.DelimitedText := Value;
      end;
    end;

    for j := 0 to PathList.Count - 1 do
      JSONArr.Add(PathList[j]);

    Key := Format('%s.%s..%s', [PkgName, PkgId, EPKey]);
    JsonPart := Format('json:{"entry":"%s","timeout":%s,"path":%s}',
      [EPKey, Timeout, JSONArr.AsJSON]);

    ResultPairs.Values[Key] := JsonPart;
  end;

begin
  ResultPairs := TStringList.Create;
  ParamList := TStringList.Create;
  PathList := TStringList.Create;
  JSONArr := TJSONArray.Create;

  try
    Sections := Manifest.Arrays['sections'];
    if Sections = nil then
      raise Exception.Create('Manifest has no sections.');

    Attrs := FindSectionWithAttrs(Sections, ['Package-Name', 'Package-Id']);
    if Attrs = nil then
      raise Exception.Create('No section with Package-Name and Package-Id');

    PkgName := GetAttr(Attrs, 'Package-Name');
    PkgId := GetAttr(Attrs, 'Package-Id');

    for i := 0 to Sections.Count - 1 do
    begin
      Section := Sections.Objects[i];
      if Section = nil then Continue;

      Attrs := Section.Objects['_'];
      if Attrs = nil then Continue;

      ParseEntryPoint(GetAttr(Attrs, 'Entry-Point-Key'), GetAttr(Attrs, 'Entry-Point'));
    end;

    Result := ResultPairs;
  finally
    ParamList.Free;
    PathList.Free;
    JSONArr.Free;
  end;
end;

function ExtractFilters(const DescriptorFile: string): TJSONArray;
var
  Doc: TXMLDocument;
  Filters: TJSONArray;
  Node, FilterNode, ActionNode, MimeNode, PropNode, AttrVar, AttrValue: TDOMNode;
  Action, Mime, Uris: string;
begin
  Filters := TJSONArray.Create;
  if not FileExists(DescriptorFile) then
    Exit(Filters);

  ReadXMLFile(Doc, DescriptorFile);
  try
    if Doc.DocumentElement = nil then Exit(Filters);

    Node := Doc.DocumentElement.FirstChild;
    while Assigned(Node) do
    begin
      if (Node.NodeName = 'invoke-target') then
      begin
        FilterNode := Node.FirstChild;
        while Assigned(FilterNode) do
        begin
          if (FilterNode.NodeName = 'filter') then
          begin
            ActionNode := FilterNode.FindNode('action');
            MimeNode := FilterNode.FindNode('mime-type');
            PropNode := FilterNode.FindNode('property');

            Action := '';
            Mime := '';
            Uris := '';

            if Assigned(ActionNode) then
              Action := 'actions=' + ActionNode.TextContent + ';';

            if Assigned(MimeNode) then
              Mime := 'types=' + MimeNode.TextContent + ';';

            if Assigned(PropNode) then
            begin
              AttrVar := PropNode.Attributes.GetNamedItem('var');
              AttrValue := PropNode.Attributes.GetNamedItem('value');
              if Assigned(AttrVar) and Assigned(AttrValue) and
                (AttrVar.NodeValue = 'uris') then
                Uris := 'uris=' + AttrValue.NodeValue + ';';
            end;

            Filters.Add(Action + Mime + Uris.TrimRight([';']));
          end;
          FilterNode := FilterNode.NextSibling;
        end;
      end;
      Node := Node.NextSibling;
    end;
  finally
    Doc.Free;
  end;
  Result := Filters;
end;

function GenerateInvokeEntries(const ManifestFile, DescriptorFile: string;
  InstallOrder: integer): TStringList;
var
  Manifest: TStringList;
  Line, Key, Value, PackageName, PackageId, DName: string;
  Filters: TJSONArray;
  EntryTypes: array[0..3] of record
    Suffix, EntryType, Ref: string;
    end
  = ((Suffix: ''; EntryType: 'application'; Ref: 'e1'), (Suffix: '.card.previewer';
    EntryType: 'card.previewer'; Ref: 'e1'), (Suffix: '.service'; EntryType: 'service';
    Ref: 'service'), (Suffix: '.card.composer'; EntryType: 'card.composer'; Ref: 'e1'));
  JsonEntry: TJSONObject;
  i, sepPos: integer;
begin
  Result := TStringList.Create;
  Manifest := TStringList.Create;
  Filters := nil;
  try
    if FileExists(ManifestFile) then
    begin
      Manifest.LoadFromFile(ManifestFile);
      for Line in Manifest do
      begin
        sepPos := Pos(': ', Line);
        if sepPos > 0 then
        begin
          Key := Trim(Copy(Line, 1, sepPos - 1));
          Value := Trim(Copy(Line, sepPos + 2, MaxInt));
          if Key = 'Package-Name' then PackageName := Value;
          if Key = 'Package-Id' then PackageId := Value;
        end;
      end;
    end;

    DName := PackageName + '.' + PackageId;
    Filters := ExtractFilters(DescriptorFile);

    for i := 0 to High(EntryTypes) do
    begin
      JsonEntry := TJSONObject.Create;
      try
        JsonEntry.Add('dname', DName);
        JsonEntry.Add('entry_point_ref', EntryTypes[i].Ref);
        JsonEntry.Add('type', EntryTypes[i].EntryType);
        if EntryTypes[i].EntryType = 'application' then
          JsonEntry.Add('filter', Filters.Clone)
        else
          JsonEntry.Add('filter', TJSONArray.Create);
        JsonEntry.Add('install_order', InstallOrder);
        JsonEntry.Add('transaction_id', 1);

        Result.Add(PackageName + EntryTypes[i].Suffix + ':json:' + JsonEntry.AsJSON);
      finally
        JsonEntry.Free;
      end;
    end;

  finally
    Manifest.Free;
    if Assigned(Filters) then Filters.Free;
  end;
end;

procedure CreateBar(const aBaseDir, Name: string);
var
  BasePath, AssetsDir, DataDir, MetaDir, ManifestPath: string;
  buf: string;
  fs: TFileStream;
  h: THandle;
begin
  BasePath := IncludeTrailingPathDelimiter(aBaseDir) + 'sys.data.' + Name;
  AssetsDir := IncludeTrailingPathDelimiter(BasePath) + 'assets';
  DataDir := IncludeTrailingPathDelimiter(AssetsDir) + 'data';
  MetaDir := IncludeTrailingPathDelimiter(BasePath) + 'META-INF';

  ForceDirectories(DataDir);
  ForceDirectories(MetaDir);

  h := FileCreate(IncludeTrailingPathDelimiter(AssetsDir) + 'links');
  if h <> THandle(-1) then FileClose(h);

  h := FileCreate(IncludeTrailingPathDelimiter(AssetsDir) + 'perms');
  if h <> THandle(-1) then FileClose(h);

  ManifestPath := IncludeTrailingPathDelimiter(MetaDir) + 'MANIFEST.MF';
  buf := GenerateManifestHeader(Name);
  fs := TFileStream.Create(ManifestPath, fmCreate);
  try
    if Length(buf) > 0 then
      fs.Write(buf[1], Length(buf) * SizeOf(char));
  finally
    fs.Free;
  end;
end;

procedure DeleteLinesWithPrefixes(var Lines: TStringList;
  const Prefixes: array of string);
var
  i, j: integer;
  Line: string;
begin
  i := 0;
  while i < Lines.Count do
  begin
    Line := TrimLeft(Lines[i]);
    for j := 0 to High(Prefixes) do
    begin
      if AnsiStartsStr(Prefixes[j], Line) then
      begin
        Lines.Delete(i);
        Dec(i);
        Break;
      end;
    end;
    Inc(i);
  end;
end;

procedure DeleteAllLinesWithPrefixesInMultiFileSet(const Dir, BaseName: string;
  const Prefixes: array of string);
var
  FileList, Lines: TStringList;
  TargetFile: string;
  i: integer;
begin
  FileList := TStringList.Create;
  Lines := TStringList.Create;
  try
    FindAllFiles(FileList, Dir, BaseName + '*', False);
    if FileList.Count = 0 then Exit;

    for i := 0 to FileList.Count - 1 do
    begin
      TargetFile := FileList[i];
      Lines.LoadFromFile(TargetFile);
      DeleteLinesWithPrefixes(Lines, Prefixes);
      Lines.SaveToFile(TargetFile);
    end;
  finally
    FileList.Free;
    Lines.Free;
  end;
end;

procedure ReplaceOrAddLines(var Lines: TStringList;
  const Prefixes, NewLines: array of string);
var
  i, j: integer;
  Found: array of boolean;
begin
  if Length(Prefixes) <> Length(NewLines) then
    raise Exception.Create('Prefixes and NewLines must have the same length.');

  SetLength(Found, Length(Prefixes));

  for i := 0 to Lines.Count - 1 do
  begin
    for j := 0 to High(Prefixes) do
    begin
      if not Found[j] and AnsiStartsStr(Prefixes[j], TrimLeft(Lines[i])) then
      begin
        Lines[i] := NewLines[j];
        Found[j] := True;
        Break;
      end;
    end;
  end;

  for j := 0 to High(Prefixes) do
  begin
    if not Found[j] then
      Lines.Add(NewLines[j]);
  end;
end;

procedure ReplaceOrAddLinesWithPrefixes(const FileName: string;
  const Prefixes, NewLines: array of string);
var
  Lines: TStringList;
begin
  Lines := TStringList.Create;
  try
    if FileExists(FileName) then
      Lines.LoadFromFile(FileName);

    ReplaceOrAddLines(Lines, Prefixes, NewLines);
    Lines.SaveToFile(FileName);
  finally
    Lines.Free;
  end;
end;

procedure ReplaceOrAddLinesInMultiFileSet(const Dir, BaseName: string;
  const Prefixes, NewLines: array of string);
var
  FileList, Lines: TStringList;
  TargetFile: string;
  i, j, MaxIndex, FileIndex: integer;
  Found: array of boolean;
  Line: string;
begin
  FileList := TStringList.Create;
  Lines := TStringList.Create;
  SetLength(Found, Length(Prefixes));

  try
    FindAllFiles(FileList, Dir, BaseName + '*', False);
    if FileList.Count = 0 then
      FileList.Add(IncludeTrailingPathDelimiter(Dir) + BaseName);

    MaxIndex := -1;

    for i := 0 to FileList.Count - 1 do
    begin
      TargetFile := FileList[i];
      Lines.LoadFromFile(TargetFile);

      for j := 0 to Lines.Count - 1 do
      begin
        Line := TrimLeft(Lines[j]);
        for FileIndex := 0 to High(Prefixes) do
        begin
          if not Found[FileIndex] and AnsiStartsStr(Prefixes[FileIndex], Line) then
          begin
            Lines[j] := NewLines[FileIndex];
            Found[FileIndex] := True;
            Break;
          end;
        end;
      end;

      Lines.SaveToFile(TargetFile);

      if TryStrToInt(Copy(ExtractFileExt(TargetFile), 2), FileIndex) then
      begin
        if FileIndex > MaxIndex then
          MaxIndex := FileIndex;
      end;
    end;

    TargetFile := IfThen(MaxIndex < 0, IncludeTrailingPathDelimiter(Dir) +
      BaseName, Format('%s%s.%.3d', [IncludeTrailingPathDelimiter(Dir),
      BaseName, MaxIndex]));

    if FileExists(TargetFile) then
      Lines.LoadFromFile(TargetFile)
    else
      Lines.Clear;

    for j := 0 to High(Prefixes) do
    begin
      if not Found[j] then
        Lines.Add(NewLines[j]);
    end;

    Lines.SaveToFile(TargetFile);

  finally
    FileList.Free;
    Lines.Free;
  end;
end;

procedure ReplaceOrAddInMultiFileSet(const Dir, BaseName, Prefix, NewLine: string);
begin
  ReplaceOrAddLinesInMultiFileSet(Dir, BaseName, [Prefix], [NewLine]);
end;

function ConvertManifestToNavigatorEntry(const Manifest: TJSONObject): string;
const
  DEFAULT_ICON = 'native/blackberry-tablet-default-icon.png';
  FALLBACK_ENTRY_TYPE = 'qnx/elf';
var
  Sections: TJSONArray;
  Section, Attrs: TJSONObject;
  PkgName, PkgId, DisplayName, Categories: string;
  IconsRaw, SplashRaw, Orientation, EntryType, EPExpr, EPBinary: string;
  FixedPart: string;
  i: integer;
  IconList, SplashList: TStringList;
begin
  Sections := Manifest.Arrays['sections'];
  if (Sections = nil) or (Sections.Count = 0) then
    raise Exception.Create('Manifest has no sections.');

  Attrs := nil;
  for i := 0 to Sections.Count - 1 do
  begin
    Section := Sections.Objects[i];
    if Assigned(Section) and Assigned(Section.Objects['_']) then
    begin
      Attrs := Section.Objects['_'];
      if (GetAttr(Attrs, 'Package-Name') <> '') and
        (GetAttr(Attrs, 'Package-Id') <> '') then
        Break;
    end;
  end;

  if not Assigned(Attrs) then
    raise Exception.Create('No section with Package-Name and Package-Id found.');

  PkgName := GetAttr(Attrs, 'Package-Name');
  PkgId := GetAttr(Attrs, 'Package-Id');
  DisplayName := GetAttr(Attrs, 'Display-Name');
  Categories := GetAttr(Attrs, 'Categories');
  IconsRaw := GetAttr(Attrs, 'Entry-Point-Icon');
  SplashRaw := GetAttr(Attrs, 'Entry-Point-Splash-Screen');
  Orientation := GetAttr(Attrs, 'Entry-Point-Orientation');
  EntryType := LowerCase(GetAttr(Attrs, 'Entry-Point-Type'));
  EPExpr := GetAttr(Attrs, 'Entry-Point');

  if PkgName = '' then PkgName := 'unknown';
  if PkgId = '' then PkgId := 'unknown';
  if DisplayName = '' then DisplayName := PkgName;
  if EntryType = '' then EntryType := FALLBACK_ENTRY_TYPE;
  if IconsRaw = '' then IconsRaw := DEFAULT_ICON;
  if Orientation = '' then Orientation := 'auto';

  if EPExpr = '' then
    EPBinary := 'app/native/' + PkgName
  else
    EPBinary := EPExpr;

  FixedPart := Format('%s,,,,,1,%s,,,1', [Orientation, EPBinary]);

  IconList := TStringList.Create;
  SplashList := TStringList.Create;
  try
    IconList.StrictDelimiter := True;
    IconList.Delimiter := ':';
    IconList.DelimitedText := IconsRaw;

    SplashList.StrictDelimiter := True;
    SplashList.Delimiter := ':';
    SplashList.DelimitedText := SplashRaw;

    Result := Format('%s.%s::%s,%s,%s,%s,%s', [PkgName, PkgId,
      IconList.DelimitedText, DisplayName, Categories, SplashList.DelimitedText,
      FixedPart]);
  finally
    IconList.Free;
    SplashList.Free;
  end;
end;

procedure UpdateHashes(const aBaseDir: string);
const
  EntryFmt: string =
    'Archive-Asset-Name: %s' + sLineBreak + 'Archive-Asset-SHA-512-Digest: %s' +
    sLineBreak;
var
  BaseDir, AssetDir, ManifestFile: string;
  BaseLen: integer;
  fileList, manifestList: TStringList;
  fullPath, relPath, hash: string;
begin
  BaseDir := IncludeTrailingPathDelimiter(aBaseDir);
  AssetDir := BaseDir + 'assets';
  ManifestFile := BaseDir + metafile;
  BaseLen := Length(BaseDir);

  fileList := TStringList.Create;
  try
    FindAllFiles(fileList, AssetDir, '*', True);

    manifestList := TStringList.Create;
    try
      manifestList.Text := ManifestMain(ManifestFile);

      for fullPath in fileList do
      begin
        hash := CalcSha512(fullPath);
        relPath := Copy(fullPath, BaseLen + 1, MaxInt);
        manifestList.Add(Format(EntryFmt, [relPath, hash]));
      end;

      manifestList.SaveToFile(ManifestFile);
    finally
      manifestList.Free;
    end;
  finally
    fileList.Free;
  end;
end;

{$IFDEF LINUX}
function ChownChmodRecursive(const Path: string; const uid, gid: integer;
  const DefaultMode: cardinal = &644): boolean;
var
  SR: TSearchRec;
  FullPath: string;
  StatBuf: Stat;
  Mode: cardinal;
begin
  Result := True;

  if fpChown(PChar(Path), uid, gid) <> 0 then
    Exit(False);

  if fpStat(PChar(Path), StatBuf) <> 0 then
    Exit(False);

  if FPS_ISDIR(StatBuf.st_mode) then
    Mode := &755
  else
    Mode := DefaultMode;

  if fpChmod(PChar(Path), Mode) <> 0 then
    Exit(False);

  if not FPS_ISDIR(StatBuf.st_mode) then
    Exit(True);

  if FindFirst(Path + DirectorySeparator + '*', faAnyFile, SR) = 0 then
  begin
    repeat
      if (SR.Name = '.') or (SR.Name = '..') then
        Continue;

      FullPath := Path + DirectorySeparator + SR.Name;

      if not ChownChmodRecursive(FullPath, uid, gid, DefaultMode) then
      begin
        FindClose(SR);
        Exit(False);
      end;
    until FindNext(SR) <> 0;
    FindClose(SR);
  end;
end;

function CreateSymbolicLink(const LinkPath, TargetPath: string): boolean;
var
  Buffer: array[0..4095] of char;
  Len: ssize_t;
begin
  if fpLStat(PChar(LinkPath), nil) = 0 then
  begin
    Len := fpReadLink(PChar(LinkPath), @Buffer[0], SizeOf(Buffer) - 1);
    if Len >= 0 then
    begin
      Buffer[Len] := #0;
      if StrPas(Buffer) = TargetPath then
        Exit(True);
    end;
    fpUnlink(PChar(LinkPath));
  end;

  Result := (fpSymlink(PChar(TargetPath), PChar(LinkPath)) = 0);
end;

const
  ID_REL_PATH = 'var/etc/id';
  LINK_REL_PATH = 'apps/gid2app';
  MIN_GID = 10000;
  MAX_GID = 2147483646;

type
  EGroupIdPoolEmpty = class(Exception);

function NewGid(const mountPath: string): integer;
var
  gid: integer;
  IdFile, LinkFile: string;
  IdPath, LinkPath: string;
  FS: TFileStream;
begin
  IdPath := IncludeTrailingPathDelimiter(mountPath) + ID_REL_PATH;
  LinkPath := IncludeTrailingPathDelimiter(mountPath) + LINK_REL_PATH;

  if not DirectoryExists(IdPath) then
    if not ForceDirectories(IdPath) then
      raise Exception.Create('Failed to create ID directory: ' + IdPath);

  if not DirectoryExists(LinkPath) then
    if not ForceDirectories(LinkPath) then
      raise Exception.Create('Failed to create link directory: ' + LinkPath);

  for gid := MIN_GID to MAX_GID do
  begin
    IdFile := IdPath + DirectorySeparator + IntToStr(gid);
    LinkFile := LinkPath + DirectorySeparator + IntToStr(gid);

    if (not FileExists(IdFile)) and (not FileExists(LinkFile)) then
    begin
      FS := TFileStream.Create(IdFile, fmCreate);
      FS.Free;
      Exit(gid);
    end;
  end;

  raise EGroupIdPoolEmpty.Create('No available GID found (pool exhausted)');
end;

const
  PPS_BASE = '/var/pps/system/';
  PPS_INSTALLER = PPS_BASE + 'installer/';
  PPS_NAVIGATOR = PPS_BASE + 'navigator/';
  PPS_INSTALLER_APP = PPS_INSTALLER + 'appdetails/';
  PPS_INSTALLER_REG = PPS_INSTALLER + 'registeredapps/applications';
  PPS_NAVIGATOR_APPS = PPS_NAVIGATOR + 'applications/applications';
  PPS_BSLAUNCHER = PPS_BASE + 'bslauncher';

function InstallUnpackedBar(const bar: string; const mountPoint: string): integer;
var
  Manifest: TJSONObject;
  Pairs: TStringList;
  i, gid: integer;
  extra, pkg: string;
  BaseMount, ManifestPath, TargetAppDir, LinkPath, AppDataBase: string;
  Search, Replace: array of string;

  procedure AddOrReplace(const RelativePath, BaseName: string; const Prefixes, NewLines: array of string);
  begin
    ReplaceOrAddLinesWithPrefixes(
      IncludeTrailingPathDelimiter(BaseMount + RelativePath) + BaseName,
      Prefixes,
      NewLines
    );
  end;

  procedure EnsureAppDirs(const BasePath: string);
  var
    SubDir: string;
    SubDirs: array[0..3] of string = ('data', 'logs', 'sharewith', 'tmp');
  begin
    for SubDir in SubDirs do
      ForceDirectories(IncludeTrailingPathDelimiter(BasePath) + SubDir);
  end;

begin
  Result := 0;
  extra := '';
  gid := NewGid(mountPoint);

  BaseMount := ExcludeTrailingPathDelimiter(mountPoint);
  ManifestPath := IncludeTrailingPathDelimiter(bar) + metafile;
  Manifest := ParseManifest(ManifestPath);

  try
    pkg := GetPackageDName(Manifest);
    TargetAppDir := IncludeTrailingPathDelimiter(BaseMount) + 'apps' + DirectorySeparator + pkg;

    if not SameFileName(ExpandFileName(bar), ExpandFileName(TargetAppDir)) then
    begin
      if DirectoryExists(TargetAppDir) and not DeleteDirectory(TargetAppDir, False) then
        raise Exception.CreateFmt('Failed to remove existing directory: %s', [TargetAppDir]);

      if not CopyDirTree(bar, IncludeTrailingPathDelimiter(TargetAppDir), [cffOverwriteFile, cffCreateDestDirectory]) then
        raise Exception.CreateFmt('Failed to copy %s -> %s', [bar, TargetAppDir]);
    end;

    if not ChownChmodRecursive(TargetAppDir, 89, gid) then
      raise Exception.CreateFmt('Failed to set ownership/mode recursively for %s to 89:%d', [TargetAppDir, gid]);

    AppDataBase := BaseMount + '/accounts/1000/_startup_data/appdata/' + pkg;
    EnsureAppDirs(AppDataBase);

    if not ChownChmodRecursive(BaseMount + '/accounts/1000/_startup_data/appdata/', 1000, gid) then
      raise Exception.CreateFmt('Failed to set ownership/mode recursively for %s to 1000:%d', [TargetAppDir, gid]);

    LinkPath := IncludeTrailingPathDelimiter(BaseMount) + 'apps' + DirectorySeparator +
      'gid2app' + DirectorySeparator + IntToStr(gid);
    if not CreateSymbolicLink(LinkPath, TargetAppDir) then
      raise Exception.CreateFmt('Failed to create symbolic link: %s -> %s', [LinkPath, TargetAppDir]);

    ReplaceOrAddInMultiFileSet(
      BaseMount + PPS_INSTALLER_APP, 'applications',
      pkg,
      ConvertManifestToApplications(Manifest, gid, extra)
    );

    AddOrReplace(PPS_INSTALLER_REG, '', [pkg],
      [ConvertManifestToRegisteredApp(Manifest, gid, extra)]);

    Pairs := ConvertManifestToServices(Manifest);
    try
      SetLength(Search, Pairs.Count);
      SetLength(Replace, Pairs.Count);
      for i := 0 to Pairs.Count - 1 do
      begin
        Search[i] := Pairs.Names[i];
        Replace[i] := Search[i] + '..' + Pairs.ValueFromIndex[i];
      end;
      AddOrReplace(PPS_BSLAUNCHER, '', Search, Replace);
    finally
      Pairs.Free;
    end;

    AddOrReplace(PPS_NAVIGATOR_APPS, '', [pkg],
      [ConvertManifestToNavigatorEntry(Manifest)]);

  finally
    Manifest.Free;
  end;
end;
{$ENDIF}

end.
