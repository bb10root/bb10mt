unit qcfm;

{$mode ObjFPC}{$H+}{$O+}

interface

uses
  Classes,
  qcfm_types,
  qcfm_utils,
  qcfm_streams,
  qcfm_packer,
  uMisc;

type
  TMultiHeaderFileV1 = qcfm_types.TMultiHeaderFileV1;
  TControlFileV1 = qcfm_types.TControlFileV1;
  TRunRecordV1 = qcfm_types.TRunRecordV1;
  TMultiHeaderFileV2 = qcfm_types.TMultiHeaderFileV2;
  TControlFileV2 = qcfm_types.TControlFileV2;
  TRunRecordV2 = qcfm_types.TRunRecordV2;
  TRRChunk = qcfm_types.TRRChunk;
  TMFCQChunk = qcfm_types.TMFCQChunk;
  TMFCQChunkArray = qcfm_types.TMFCQChunkArray;
  TMFCQChunkArrays = qcfm_types.TMFCQChunkArrays;
  TMFCQVersion = qcfm_types.TMFCQVersion;
  TBlockMapItem = qcfm_types.TBlockMapItem;
  TVirtualBlockMap = qcfm_types.TVirtualBlockMap;
  AVirtualBlockMap = qcfm_types.AVirtualBlockMap;
  TFileStreamMap = qcfm_types.TFileStreamMap;

  TMFCQChunkStream = qcfm_streams.TMFCQChunkStream;
  TMFCQContainerStream = qcfm_streams.TMFCQContainerStream;
  TMFCQPackStream = qcfm_streams.TMFCQPackStream;

function AnalyzeMFCQChunks(inFile: TStream): TMFCQChunkArrays; inline;
function AnalyzeMFCQChunks(const FileName: string): TMFCQChunkArrays; inline;
procedure Chunk2Stream(inFile: TStream; const chunk: TMFCQChunk;
  outFile: TStream; cb: TProgressCallback = nil; outFileName: string = ''); inline;

procedure unpackMFCQ(fileName: string; cb: TProgressCallback = nil;
  const OutDir: string = ''); inline;
procedure packMFCQ(oFile: string; const iFiles: TStringList;
  cb: TProgressCallback = nil; ver: integer = 2; fast: boolean = False;
  sign: boolean = False); inline;
procedure _packMFCQ(outFile: TStream; const iFiles: TStringList;
  cb: TProgressCallback = nil; ver: integer = 2; fast: boolean = False;
  sign: boolean = False); inline;

function Type2Ext(t: integer): string; inline;
function Ext2Type(const t: string): integer; inline;
function Size2Blocks(const FileName: string; bs: integer = $10000): integer; inline;

implementation

function AnalyzeMFCQChunks(inFile: TStream): TMFCQChunkArrays;
begin
  Result := qcfm_packer.AnalyzeMFCQChunks(inFile);
end;

function AnalyzeMFCQChunks(const FileName: string): TMFCQChunkArrays;
begin
  Result := qcfm_packer.AnalyzeMFCQChunks(FileName);
end;

procedure Chunk2Stream(inFile: TStream; const chunk: TMFCQChunk;
  outFile: TStream; cb: TProgressCallback; outFileName: string);
begin
  qcfm_packer.Chunk2Stream(inFile, chunk, outFile, cb, outFileName);
end;

procedure unpackMFCQ(fileName: string; cb: TProgressCallback; const OutDir: string);
begin
  qcfm_packer.unpackMFCQ(fileName, cb, OutDir);
end;

procedure packMFCQ(oFile: string; const iFiles: TStringList;
  cb: TProgressCallback; ver: integer; fast: boolean; sign: boolean);
begin
  qcfm_packer.packMFCQ(oFile, iFiles, cb, ver, fast, sign);
end;

procedure _packMFCQ(outFile: TStream; const iFiles: TStringList;
  cb: TProgressCallback; ver: integer; fast: boolean; sign: boolean);
begin
  qcfm_packer._packMFCQ(outFile, iFiles, cb, ver, fast, sign);
end;

function Type2Ext(t: integer): string;
begin
  Result := qcfm_utils.Type2Ext(t);
end;

function Ext2Type(const t: string): integer;
begin
  Result := qcfm_utils.Ext2Type(t);
end;

function Size2Blocks(const FileName: string; bs: integer): integer;
begin
  Result := qcfm_utils.Size2Blocks(FileName, bs);
end;

end.
