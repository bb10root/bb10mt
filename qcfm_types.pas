unit qcfm_types;

{$mode ObjFPC}{$H+}{$O+}

interface

uses
  Classes, SysUtils, Generics.Collections;

const
  imageNVRAM = $03;
  imageUFS = $05;
  imageMBR = $06;
  imageSIG = $07;
  imageIFS = $08;
  imageRFS = $09;
  imageR_MBR = $0A;
  imageR_SIG = $0B;
  imageR_RFS = $0C;
  imageCalWork = $0F;
  imageCalBackup = $10;
  imageDMI = $11;
  imageDMI_MBR = $12;
  imageDMI_FSYS = $13;
  imageOS = $18;
  imageSIG2 = $89;
  imageR_SIG2 = $8C;
  imageDMI_SIG2 = $93;

  defaultBlockSize = $10000;

type
  TMultiHeaderFileV1 = packed record
    magic: array[0..3] of char;
    checksum: dword;
    version: dword;
    nheaders: dword;
    headersz: dword;
    datachecksum: dword;
    flags: dword;
    dummy: array[0..3] of char;
  end;

  TControlFileV1 = packed record
    magic: array[0..3] of char;
    checksum: dword;
    version: dword;
    nrecords: dword;
    blocksize: dword;
    device: dword;
    partition: dword;
    datachecksum: dword;
    flags: dword;
    dummy: array[0..3] of char;
  end;

  TRunRecordV1 = packed record
    offset: integer;
    Count: dword;
  end;

  TMultiHeaderFileV2 = packed record
    magic: array[0..3] of char;
    header_cksum: dword;
    version: dword;
    length: dword;
    nheaders: dword;
    headersz: dword;
    data_crc: dword;
  end;

  TControlFileV2 = packed record
    magic: array[0..3] of char;
    version: dword;
    length: dword;
    _type: dword;
    rrecOffset: dword;
    nrecords: dword;
    hwvOffset: dword;
    hwvNumEntries: dword;
    sigOffset: dword;
    sigSize: dword;
    blocksize: dword;
  end;

  TRunRecordV2 = packed record
    magic: array[0..3] of char;
    length: dword;
    offset: dword;
    Count: dword;
  end;

  TRRChunk = record
    Offset: int64;
    Count: integer;
  end;

  TMFCQChunk = record
    Offset: int64;
    Size: int64;
    Flags: dword;
    ChunkType: string;
    BlockCount: integer;
    BlockSize: integer;
    RR: array of TRRChunk;
  end;

  TMFCQChunkArray = array of TMFCQChunk;

  TMFCQChunkArrays = record
    V1: TMFCQChunkArray;
    V2: TMFCQChunkArray;
  end;

  TMFCQVersion = (mfcqUnknown, mfcqV1, mfcqV2, mfcqHybrid);

  TBlockMapItem = record
    VirtOffset: int64;
    PhysOffset: int64;
  end;

  TVirtualBlockMap = record
    VirtualOffset: int64;
    SourceFileIdx: integer;
    FileOffset: int64;
    BlockSize: integer;
  end;

  AVirtualBlockMap = array of TVirtualBlockMap;
  TFileStreamMap = specialize TObjectDictionary<integer, TFileStream>;

  TBlockRange = record
    BlockIndex: integer;
    Count: integer;
  end;

  TBlockRangeArray = array of TBlockRange;

const
  signature_data: array[0..559] of byte = (
    $51, $4E, $58, $48, $2D, $4F, $53, $2D, $31, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
    $51, $4E, $58, $48, $88, $00, $00, $00, $D1, $42, $E9, $27, $E7, $AB, $A7, $FD,
    $1D, $8B, $6A, $C6, $F1, $58, $A4, $46, $92, $DA, $24, $AB, $22, $F1, $EA, $DE,
    $06, $12, $A9, $05, $37, $46, $F3, $BE, $01, $39, $AF, $C7, $F4, $A1, $F7, $93,
    $AF, $B6, $14, $33, $7B, $69, $47, $C8, $BA, $D9, $0F, $9B, $9F, $FF, $7A, $D3,
    $05, $D4, $78, $F1, $6B, $E5, $1C, $81, $30, $00, $00, $00, $46, $A1, $6C, $1E,
    $52, $A3, $A7, $C0, $58, $68, $0D, $3E, $D6, $85, $E0, $5B, $09, $E3, $6D, $A9,
    $BF, $20, $0D, $3B, $52, $C6, $DF, $3A, $4F, $B9, $48, $76, $F1, $68, $CC, $5F,
    $F8, $A6, $CA, $CE, $F3, $E5, $19, $BB, $EF, $E6, $F8, $D9, $B0, $9A, $25, $2B,
    $F2, $FB, $04, $BF, $0C, $BF, $98, $9E, $15, $4D, $01, $08, $53, $01, $00, $00,
    $BC, $00, $00, $00, $01, $00, $01, $00, $FD, $0B, $A6, $B5, $51, $4E, $58, $4C,
    $2D, $4F, $53, $2D, $31, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $51, $4E, $58, $4C,
    $88, $00, $00, $00, $99, $C4, $EC, $AC, $02, $E1, $E2, $E2, $7E, $3B, $66, $9F,
    $62, $4A, $41, $05, $95, $B6, $75, $2E, $72, $8A, $38, $78, $03, $54, $C8, $6F,
    $80, $3A, $5F, $5F, $6F, $4D, $63, $AF, $08, $94, $B4, $5F, $3F, $28, $91, $B7,
    $CF, $6A, $6E, $95, $FE, $DA, $64, $36, $F4, $57, $60, $84, $CC, $3F, $26, $9B,
    $2F, $53, $7E, $70, $80, $00, $00, $00, $DA, $81, $84, $05, $E4, $FE, $84, $AD,
    $FE, $9A, $40, $C1, $BA, $BE, $0B, $C9, $A8, $FA, $B7, $23, $73, $E4, $52, $07,
    $3A, $22, $E3, $EE, $E1, $19, $CF, $27, $51, $AF, $8A, $94, $89, $85, $5F, $01,
    $EC, $D0, $75, $1D, $42, $E7, $39, $40, $DF, $CF, $41, $75, $81, $AF, $58, $11,
    $EF, $66, $F2, $C8, $48, $9D, $22, $92, $76, $00, $00, $00, $BC, $00, $00, $00,
    $01, $00, $01, $00, $0E, $1C, $B7, $C6, $51, $4E, $58, $2D, $4F, $53, $2D, $31,
    $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $00, $51, $4E, $58, $00, $80, $00, $00, $00,
    $BB, $AA, $BF, $CE, $E4, $A0, $9D, $14, $9F, $DC, $B4, $CA, $DF, $35, $B7, $F3,
    $B5, $A2, $C1, $6C, $3A, $92, $00, $10, $F0, $B1, $7E, $3F, $F0, $23, $E2, $BA,
    $FD, $D7, $A8, $0D, $E7, $B5, $A3, $69, $5E, $72, $2D, $FF, $8B, $F7, $A7, $99,
    $74, $75, $64, $48, $6A, $2E, $62, $61, $C7, $F5, $55, $34, $41, $8F, $7A, $90,
    $A3, $05, $C6, $3E, $41, $47, $84, $D3, $51, $05, $46, $4C, $F9, $A0, $B9, $52,
    $1E, $1A, $21, $8B, $EE, $94, $16, $BB, $CA, $F3, $16, $AF, $E0, $22, $8E, $16,
    $62, $42, $5B, $81, $43, $7E, $B0, $6E, $F9, $FE, $E3, $98, $86, $DF, $8F, $25,
    $E0, $DA, $F5, $9C, $00, $D8, $74, $30, $0B, $01, $1D, $D8, $5F, $91, $8A, $9D,
    $B4, $00, $00, $00, $01, $00, $01, $00, $1F, $2D, $C8, $D7, $23, $98, $F2, $4D);

implementation

end.
