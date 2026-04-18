unit NVRE;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils;

implementation

uses crc;

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

function ReadNVRAMBlock(Stream: TStream): TNVRAMBlock;
var
  Block: TNVRAMBlock;
  HeaderSize: integer;
begin
  HeaderSize := SizeOf(TNVRAMBlockHeader);

  if Stream.Read(Block.Header, HeaderSize) <> HeaderSize then
    raise Exception.Create('Cannot read NVRAM header');

  SetLength(Block.Data, Block.Header.DataLen);

  if Stream.Read(pbyte(Block.Data)^, Block.Header.DataLen) <> Block.Header.DataLen then
    raise Exception.Create('Cannot read NVRAM data');

  if Stream.Read(Block.Magic, 4) <> 4 then
    raise Exception.Create('Cannot read NVRAM magic');

  Result := Block;
end;

function IsValidNVRAMBlock(const Block: TNVRAMBlock): boolean;
var
  CalcDataCRC, CalcHdrCRC: DWord;
begin
  // Обчислюємо CRC32 від Block.Data
  CalcDataCRC := crc32(0, @Block.Data[0], Block.Header.DataLen);

  if CalcDataCRC <> Block.Header.DataCrc then
    Exit(False);

  // Обчислення CRC32 тільки з перших 7 полів (до HdrCrc)
  CalcHdrCRC := crc32(0, @Block.Header, SizeOf(TNVRAMBlockHeader) - SizeOf(DWord));

  Result := (CalcHdrCRC = Block.Header.HdrCrc) and (Block.Magic = $4552564E); // 'NVRE'
end;


end.
