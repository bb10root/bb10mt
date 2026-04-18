unit uRAW;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  CLI.Interfaces,    // Core interfaces
  CLI.Command,       // Base command implementation
  CLI.Progress,      // Optional: Progress indicators
  CLI.Console;       // Optional: Colored console output


type
  TRawCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

  TNVRAMCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;


  TMCTCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;


var
  RawCommand: TRawCommand;
  NVRAMCommand: TNVRAMCommand;
  MCTCommand: TMCTCommand;

implementation

uses nvre, mct, uMisc;

function TRawCommand.Execute: integer;
begin

end;

function TNVRAMCommand.Execute: integer;
var
  fileName, outDir: string;
  Stream: TFileStream;
begin
  GetParameterValue('--input', fileName);
  if not GetParameterValue('--output', outDir) then
    outDir := ExtractFileDir(fileName);
  if FileExists(fileName) then
  begin
    ForceDirectories(outDir);
    Stream := TFileStream.Create(fileName, fmOpenRead);
    try
      ExtractNVRAMBlocks(Stream, outDir);
    finally
      FreeAndNil(Stream)
    end;
  end;
end;

function TMCTCommand.Execute: integer;
var
  fileName, outDir, off: string;
  offset: int64 = 0;
begin
  GetParameterValue('--input', fileName);
  if GetParameterValue('--mct', off) then
    TryStrToInt64AutoBase(off, offset);
  if not GetParameterValue('--output', outDir) then
    outDir := ExtractFileDir(fileName);
  if FileExists(fileName) then
  begin
    ForceDirectories(outDir);
    RunExtract(fileName, outDir, offset);
  end;
end;


initialization
  RawCommand := TRawCommand.Create('raw', 'process raw data');

  NVRAMCommand := TNVRAMCommand.Create('nvram', 'split NVRAM to individual blocks');
  NVRAMCommand.AddPathParameter('-i', '--input', 'input file', True);
  NVRAMCommand.AddPathParameter('-o', '--output', 'input dir', False);

  MCTCommand := TMCTCommand.Create('dump', 'split raw flash image to partitions');
  MCTCommand.AddPathParameter('-i', '--input', 'input file', True);
  MCTCommand.AddPathParameter('-o', '--output', 'input dir', False);
  MCTCommand.AddIntegerParameter('-m', '--mct', 'MCT offset', False);
  RawCommand.AddSubCommand(MCTCommand);
  RawCommand.AddSubCommand(NVRAMCommand);

end.
