unit QNX.Debloat;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, qnx6, QNX.Utils;

type
  TApplyChmodProc = function(FS: TQNX6Fs; const Path: string;
    Mode: integer; Recursive: boolean): integer;

procedure GenUninstallScript(BlackList: TStringList; WhiteList: TStringList;
  msData: TMemoryStream);
function ParseAppNamesFromStream(AMemoryStream: TMemoryStream): TStringArray;

// Перевантажені процедури
procedure UninstallApps(FS: TQNX6Fs; BlackList: TStringList;
  ChmodProc: TApplyChmodProc); overload;
procedure UninstallApps(FS: TQNX6Fs; BlackList: TStringList); overload;

implementation

uses CLI.Console;

procedure GenUninstallScript(BlackList: TStringList; WhiteList: TStringList;
  msData: TMemoryStream);
var
  i: integer;
begin
  msData.Clear;

  if (BlackList = nil) or (BlackList.Count = 0) then Exit;

  if (WhiteList <> nil) and (WhiteList.Count > 0) then
  begin
    WhiteList.Sorted := True;
    for i := BlackList.Count - 1 downto 0 do
    begin
      if WhiteList.IndexOf(BlackList[i]) >= 0 then
        BlackList.Delete(i);
    end;
  end;

  if BlackList.Count = 0 then Exit;

  BlackList.SaveToStream(msData);
end;

procedure UninstallApps(FS: TQNX6Fs; BlackList: TStringList;
  ChmodProc: TApplyChmodProc); overload;
const
  DEBLOAT_SCRIPT_PATH = '/accounts/devuser/rootdata/debloat.txt';
  OCTAL_777 = $1FF;
var
  msData: TMemoryStream;
  WhiteList: TStringList;
  ParentDir: string;
begin
  if (FS = nil) or (BlackList = nil) or (BlackList.Count = 0) then Exit;

  msData := TMemoryStream.Create;
  try
    WhiteList := TStringList.Create;
    try
      WhiteList.AddStrings(['sys.android', 'sys.android.shell']);
      GenUninstallScript(BlackList, WhiteList, msData);
    finally
      FreeAndNil(WhiteList);
    end;

    if msData.Size > 0 then
    begin
      // Отримуємо тільки шлях до папки: '/accounts/devuser/rootdata/'
      ParentDir := ExtractPOSIXFilePath(DEBLOAT_SCRIPT_PATH);

      // Створюємо батьківські директорії, а не сам файл як папку
      qnx6_MkDir(FS, ParentDir, True);

      FS.CreateFile(PChar(DEBLOAT_SCRIPT_PATH), OCTAL_777);
      if qnx6_writeFile(FS, DEBLOAT_SCRIPT_PATH, msData) = 0 then
      begin
        TConsole.WriteLn('Successfully created debloat script at: ' +
          DEBLOAT_SCRIPT_PATH);
        if Assigned(ChmodProc) then
          ChmodProc(FS, DEBLOAT_SCRIPT_PATH, OCTAL_777, False);
      end
      else
        TConsole.WriteLn(Format('Error: Failed to write uninstall script to %s',
          [DEBLOAT_SCRIPT_PATH]));
    end;
  finally
    FreeAndNil(msData);
  end;
end;

procedure UninstallApps(FS: TQNX6Fs; BlackList: TStringList); overload;
begin
  UninstallApps(FS, BlackList, nil);
end;

function ParseAppNamesFromStream(AMemoryStream: TMemoryStream): TStringArray;
var
  StringList, ResultList: TStringList;
  I, DoubleColonPos, CommaPos, HashLength: integer;
  Line, LeftPart, RightPart, OriginalHash: string;
begin
  SetLength(Result, 0);
  if (AMemoryStream = nil) or (AMemoryStream.Size = 0) then Exit;

  StringList := TStringList.Create;
  ResultList := TStringList.Create;
  try
    AMemoryStream.Position := 0;
    StringList.LoadFromStream(AMemoryStream);

    for I := 0 to StringList.Count - 1 do
    begin
      Line := Trim(StringList[I]);

      if (Line = '') or (Line[1] = '@') then Continue;

      DoubleColonPos := Pos('::', Line);
      if DoubleColonPos > 0 then
      begin
        LeftPart := Copy(Line, 1, DoubleColonPos - 1);
        RightPart := Copy(Line, DoubleColonPos + 2, MaxInt);

        CommaPos := Pos(',', RightPart);
        if CommaPos > 0 then
          OriginalHash := Copy(RightPart, 1, CommaPos - 1)
        else
          OriginalHash := RightPart;

        HashLength := Length(OriginalHash);

        if (HashLength > 0) and (Length(LeftPart) > HashLength + 1) then
          ResultList.Add(Copy(LeftPart, 1, Length(LeftPart) - HashLength - 1))
        else
          ResultList.Add(LeftPart);
      end;
    end;

    if ResultList.Count > 0 then
    begin
      SetLength(Result, ResultList.Count);
      for I := 0 to ResultList.Count - 1 do
        Result[I] := ResultList[I];
    end;
  finally
    FreeAndNil(StringList);
    FreeAndNil(ResultList);
  end;
end;

end.
