unit nvre;

interface

uses
  SysUtils, Classes, crc;

procedure ExtractNVRAMBlocks(Stream: TStream; const OutputDir: string);

implementation


type
  TNVRAMBlockHeader = packed record
    unk1: word;
    BlockNum: word;
    Revision: DWord;
    DataCrc: DWord;
    unk2: DWord;
    BlockLen: DWord;
    DataLen: DWord;
    HdrCrc: DWord;
  end;

  TNVRAMBlock = record
    Header: TNVRAMBlockHeader;
    Data: array of byte;
    Magic: DWord;
  end;

const
  HeaderSize = SizeOf(TNVRAMBlockHeader);


function ReadOneNVRAMBlock(Stream: TStream; var Block: TNVRAMBlock): boolean;
begin
  Result := False;

  if Stream.Position + HeaderSize + 4 > Stream.Size then Exit;

  if Stream.Read(Block.Header, HeaderSize) <> HeaderSize then Exit;

  if Stream.Position + Block.Header.DataLen + 4 > Stream.Size then Exit;

  SetLength(Block.Data, Block.Header.DataLen);
  if Stream.Read(pbyte(Block.Data)^, Block.Header.DataLen) <> Block.Header.DataLen then Exit;

  if Stream.Read(Block.Magic, 4) <> 4 then Exit;

  Result := True;
end;

function IsValidNVRAMBlock(const Block: TNVRAMBlock): boolean;
var
  DataCRC, HdrCRC: DWord;
begin
  if Length(Block.Data) <> Block.Header.DataLen then Exit(False);
  if Block.Magic <> $4552564E then Exit(False); // 'NVRE'

  if Block.Header.DataLen > 0 then
  begin
    DataCRC := crc32(0, @Block.Data[0], Block.Header.DataLen);
    if DataCRC <> Block.Header.DataCrc then Exit(False);
  end;

  HdrCRC := crc32(0, @Block.Header, SizeOf(Block.Header) - SizeOf(DWord));
  if HdrCRC <> Block.Header.HdrCrc then Exit(False);

  Result := True;
end;

procedure ExtractNVRAMBlocks(Stream: TStream; const OutputDir: string);
var
  Block: TNVRAMBlock;
  FilenameBase, Filename, Key: string;
  FS: TFileStream;
  Index: integer;
  CountMap: TStringList;
  Count: integer;
  SavedPos: int64;
begin
  ForceDirectories(OutputDir);

  CountMap := TStringList.Create;
  CountMap.Sorted := True;
  CountMap.Duplicates := dupIgnore;

  Index := 0;
  while Stream.Position < Stream.Size do
  begin
    SavedPos := Stream.Position;
    if not ReadOneNVRAMBlock(Stream, Block) then
    begin
      WriteLn('Error reading block at offset ', SavedPos);
      Stream.Position := (SavedPos + $10000) and $FFFF0000;
      //Break;
    end;

    if not IsValidNVRAMBlock(Block) then
    begin
      // WriteLn('Invalid block #', Index, ' skipped');
      Continue;
    end;
    Inc(Index);

    Key := Format('%0.4x+%8.8x', [Block.Header.BlockNum, Block.Header.Revision]);

    // Підрахунок екземплярів для одного ключа
    Count := CountMap.IndexOf(Key);
    if Count = -1 then
    begin
      CountMap.AddObject(Key, TObject(PtrInt(1)));
      Filename := Format('%s%s.bin', [IncludeTrailingPathDelimiter(OutputDir), Key]);
    end
    else
    begin
      // Отримати попередній лічильник
      Count := PtrInt(CountMap.Objects[Count]);
      Inc(Count);
      CountMap.Objects[CountMap.IndexOf(Key)] := TObject(PtrInt(Count));
      Filename := Format('%s%s_%d.bin', [IncludeTrailingPathDelimiter(OutputDir), Key, Count]);
    end;

    FS := TFileStream.Create(Filename, fmCreate);
    try
      if Length(Block.Data) > 0 then
        FS.WriteBuffer(Block.Data[0], Length(Block.Data));
      WriteLn('Saved: ', Filename);
    finally
      FS.Free;
    end;

    Stream.Position := SavedPos + Block.Header.BlockLen;
  end;

  CountMap.Free;
end;

end.
