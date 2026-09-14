unit scripthandler;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils;

procedure runScript(imagePath, scriptName: string);

implementation

uses uScript, qnx6.types, qnx6, QNX.Commands.Script;

procedure runScript(imagePath, scriptName: string);
var
  CmdList: ICommandList;
  fStream: TFileStream;
  QNX: TQNX6Fs;
  line: string;
  script : TStringList;
begin
  fStream := nil;
  QNX := nil;

  fStream := TFileStream.Create(imagePath, fmOpenReadWrite);
  try
    QNX := TQNX6Fs.Create(fStream);
    try
      QNX.Open(True);

      script := TStringList.Create;
      try
        script.LoadFromFile(scriptName);
        CmdList := TCommandList.Create;
        CmdList.RegisterCommand(
          TMkDirCommand.Create('mkdir', 'create directory', 'mkdir [-p] <path>', QNX));
        CmdList.RegisterCommand(
          TPushCommand.Create('push', 'push file/dir to image', 'push <src path> <dst path>', QNX));
        CmdList.RegisterCommand(
          TTouchCommand.Create('touch', 'create empty file', 'touch <file>', QNX));
        CmdList.RegisterCommand(
          TChmodCommand.Create('chmod', 'change file/dir mode', 'chmod [-R] <mode> <path>', QNX));
        CmdList.RegisterCommand(
          TChownCommand.Create('chown', 'change file/dir owner',
          'chown [-R] <user>:<group> <path>', QNX));
        CmdList.RegisterCommand(
          TReplaceCommand.Create('replace', 'replace substring in file',
          'replace <file> <old> <new>', QNX));
        CmdList.RegisterCommand(
          TRemoveAppCommand.Create('removeapp', 'remove preinstalled app',
          'removeapp <appID_1>..<appID_N>', QNX));
        CmdList.RegisterCommand(
          TRmCommand.Create('rm', 'remove file/dir mode', 'chmod [-R] <path>', QNX));
        CmdList.RegisterCommand(
          TAddStringCommand.Create('addstring', 'add string to file', 'addstring <file> <string>', QNX));

        for line in script do
          CmdList.ExecuteCommand(line);
      finally
        FreeAndNil(script);
      end;

      QNX.Close;
    finally
      FreeAndNil(QNX);
    end;
  finally
    FreeAndNil(fStream);
  end;

end;

end.
