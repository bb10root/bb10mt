const
  QNX6FS_NAME_MAX = 510;
  QNX6FS_SYMLINK_MAX = 512;

  QNX6FS_PATH_MAX = 1024;

  QNX6FS_DIRECT_BLKS = 16;
  QNX6FS_INDIRECT_LEVELS = 3;
  QNX6FS_UNUSED_BLK = $FFFFFFFF;

  (* Flags for 'q6_dinode_t.i_flags'
   *)

  QNX6FS_INO_USED = $01;
  QNX6FS_INO_MODIFIED = $02;


(*  The .iextra file is organized as a set of fixed size records
 *  and only the first record is fixed as the keylist.
 *)
  QNX6FS_IEXTRA_VERSION = 1;
  QNX6FS_IEXTRA_SIZE = 512;
  QNX6FS_IEXTRA_TRAILER = 16;

  QNX6FS_IEXTRA_UNUSED = 0;
  QNX6FS_IEXTRA_DOMAIN_LIST = 1; (* encryption related record *)
  QNX6FS_IEXTRA_DOMAIN_KEY = 2;  (* encryption related record *)
  QNX6FS_IEXTRA_FILE_KEY = 3; (* encryption related record *)
  QNX6FS_IEXTRA_FILE_NAME = 4; (* encryption related record *)
  QNX6FS_IEXTRA_ATTRIBUTE = 5; (* encryption related record *)
  QNX6FS_IEXTRA_ACL = 6;       (* persistent ACL record *)

  QNX6FS_IEXTRA_SALT_SIZE = 64;
  QNX6FS_IEXTRA_KEY_SIZE = (512 div 8);
  QNX6FS_IEXTRA_MAX_KEY_SIZE = (2048 div 8);

  QNX6FS_DOMAIN_UNUSED = 0;
  QNX6FS_DOMAIN_MAX = ((QNX6FS_IEXTRA_SIZE - QNX6FS_IEXTRA_TRAILER) div 4 - 2);


(*  Flags used in the public iextra record information (trailer)
*)

(*  The mask of valid bits describing the migration state. If any bit is set in
  this mask, the file is undergoing some form of migration. The migration
  state values are NOT binary exclusive. Since only four states can ever
  exist, we only use 2 bits to store the state.
*)
  QNX6FS_IEXTRA_FLAG_MIGRATION = $03;
(*  The file is being migrated from plaintext 'P' to ciphertext 'C'.
*)
  QNX6FS_IEXTRA_FLAG_MIGRATION_P2C = $01;
(*  The file is being migrated from ciphertext 'C' to plaintext 'P'.
*)
  QNX6FS_IEXTRA_FLAG_MIGRATION_C2P = $02;
(*  The file is being migrated from ciphertext 'C' produced from one key to
  ciphertext 'C' produced by a different key.

  This flag is currently not supported.
*)
  QNX6FS_IEXTRA_FLAG_MIGRATION_C2C = $03;
(*  Flags saved exclusively in the domain list entry of the iextra file.
  These flags cannot use the lower 2 bits since that is technically reserved
  for migration, even if these flags should never be set on the same record.
*)

(*  Defines if the whole disk is being encrypted under one domain.
  This will assume all plaintext files are 'tagged' to be migrated.
*)
  QNX6FS_IEXTRA_FLAG_DL_WHOLE_DISK = $04;

(*  Defines if we need to hide plaintext files from the caller, and only make then
  visible when they have been completely migrated into their encrypted state.
*)
  QNX6FS_IEXTRA_FLAG_DL_HIDE_PT = $08;

  QNX6FS_DIR_EOF = $00;
  QNX6FS_DIR_LONGNAME = $FF;
  QNX6FS_DIR_CRYPTNAME = $FE;
  QNX6FS_DIR_DELETED = 0;
  QNX6FS_DIR_SHORT_LEN = 27;

  QNX6FS_F32_SEED_INOD = $9c2d0c41;
  QNX6FS_CRC32_SEED_INOD = $7def472b;

  QNX6FS_EMODE_ALIMIT = $1;  (* Don't allocate beyond allocation limit *)
  QNX6FS_EMODE_INPLACE = $2;  (* Do not COW the inode *)
  QNX6FS_EMODE_ANTIFRAG = $4;  (* Use anti-fragmentation alloc policy *)
  QNX6FS_EMODE_MASK = $7;  (* Mask of changeable emode bits *)

  QNX_BOOT_MAGIC = $009010EB;

  QNX6FS_SIGNATURE = $68191122;
  QNX6FS_SIGNATURE2 = $97E6EEDD;
  QNX6FS_ROOT_INODE = 1;
  QNX6FS_BOOTDIR_INODE = 2;
  QNX6FS_FSYS_VERSION = 4;
  QNX6FS_SBLK_SIZE = 512;
  QNX6FS_SBLK_RSRV = 4096;
  QNX6FS_BOOT_RSRV = 8192;
  QNX6FS_BOOTDIR_SIZE = 4096;
  QNX6FS_DEFAULT_RSRV = 3;
  QNX6FS_MAX_NGROUPS = 64;

  QNX6FS_MAX_BLK_SIZE = (32 * 1024);

(* With block sizes larger than 4KiB, an offset must be added to ensure data
   contents are aligned to the block size boundaries:
   0...8KiB-1         Boot Block
   8KiB..12KiB-1      Superblock reserved
   12KiB..Block Size  Padding
*)
  QNX6FS_MIN_RSRV_SIZE = (QNX6FS_BOOT_RSRV + QNX6FS_SBLK_RSRV);
  {$define QNX6FS_OVERHEAD_SIZE(b) := (QNX6FS_BOOT_RSRV + 2 * max(QNX6FS_SBLK_RSRV, (b))) }
  {$define QNX6FS_DATA_START(b)    := ((QNX6FS_BOOT_RSRV + QNX6FS_SBLK_RSRV)
                + ( ((b) <= QNX6FS_SBLK_RSRV) ? 0
                  : abs((b) - QNX6FS_MIN_RSRV_SIZE)) ) }

(*
 * max volume label length: overlays s_uuid[]
 *)
  QNX6FS_MAX_LABEL_LEN = 16;

  QNX6FS_SBLK_UNSTABLE = $00000001;
  QNX6FS_SBLK_V3_LE_RSRV = $00000002;
  QNX6FS_VOLUME_LABEL = $00000004;  (* Volume label is a string, not a UUID *)
  QNX6FS_LFN_CKSUM = $00000100;
  QNX6FS_IEXTRA = $00000200;
  QNX6FS_CRYPTO_NAME = $00000400;
  QNX6FS_OVERSIZED_BITMAP = $00000800;  (* Volume has oversized bitmap *)
  QNX6FS_QUOTAS = $00001000;
  QNX6FS_SBLK_V3_BE_RSRV = $40000000;
  QNX6FS_UDSGATE = $00010000;  (* forced layout change on account of unix domain socket hosting support *)
  QNX6FS_SPARSEFILES = $00020000;
  QNX6FS_MASK_INCOMPAT = $00FF0000;
  QNX6FS_MASK_READONLY = $0000FF00;

var
  bootsect: array[0..2584] of byte = ($EB, $10, $90, $00, $00, $00, $00, $00, $10,
    $00, $00, $00, $D8, $3F, $4B, $07, $00, $80, $FA, $31, $C0, $8E, $D0, $BC, $00,
    $20, $B8, $C0, $07, $50, $B8, $36, $01, $50, $CB, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $00, $00, $66, $90, $00, $00, $00, $00, $00,
    $00, $00, $00, $8D, $B4, $00, $00, $10, $00, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $FF, $FF, $00, $00, $00, $93, $00, $00, $FF,
    $FF, $00, $00, $00, $93, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $18, $00, $90, $7C, $00, $00, $00, $00, $FF,
    $FF, $00, $00, $00, $9B, $CF, $00, $FF, $FF, $00, $00, $00, $93, $CF, $00, $0D,
    $0A, $51, $4E, $58, $20, $76, $31, $2E, $32, $62, $20, $42, $6F, $6F, $74, $20,
    $4C, $6F, $61, $64, $65, $72, $00, $0D, $0A, $55, $6E, $73, $75, $70, $70, $6F,
    $72, $74, $65, $64, $20, $42, $49, $4F, $53, $00, $0D, $0A, $52, $41, $4D, $20,
    $45, $72, $72, $6F, $72, $00, $0D, $0A, $44, $69, $73, $6B, $20, $52, $65, $61,
    $64, $20, $45, $72, $72, $6F, $72, $00, $0D, $0A, $4D, $69, $73, $73, $69, $6E,
    $67, $20, $4F, $53, $20, $49, $6D, $61, $67, $65, $00, $0D, $0A, $49, $6E, $76,
    $61, $6C, $69, $64, $20, $4F, $53, $20, $49, $6D, $61, $67, $65, $00, $0D, $0A,
    $55, $6E, $73, $75, $70, $70, $6F, $72, $74, $65, $64, $20, $4D, $75, $6C, $74,
    $69, $2D, $42, $6F, $6F, $74, $00, $3A, $20, $00, $0D, $0A, $00, $0E, $1F, $88,
    $16, $11, $00, $FB, $FC, $F6, $06, $03, $00, $02, $74, $03, $E8, $3F, $00, $F6,
    $06, $03, $00, $01, $75, $06, $BE, $A8, $00, $E8, $3C, $00, $BB, $AA, $55, $B4,
    $41, $CD, $13, $72, $21, $81, $FB, $55, $AA, $75, $1B, $F6, $C1, $01, $74, $16,
    $B8, $00, $02, $50, $8E, $C0, $B8, $00, $02, $50, $66, $31, $C0, $89, $C7, $BB,
    $08, $00, $E8, $40, $00, $CB, $BE, $C0, $00, $E8, $0C, $00, $EB, $53, $B4, $0F,
    $CD, $10, $83, $E0, $7F, $CD, $10, $C3, $AC, $08, $C0, $74, $09, $BB, $07, $00,
    $B4, $0E, $CD, $10, $EB, $F2, $C3, $66, $03, $06, $04, $00, $BE, $40, $00, $89,
    $5C, $02, $89, $7C, $04, $8C, $44, $06, $66, $89, $44, $08, $8A, $16, $11, $00,
    $B4, $42, $CD, $13, $C3, $56, $E8, $DE, $FF, $72, $02, $5E, $C3, $BE, $DF, $00,
    $E8, $C5, $FF, $EB, $0C, $E8, $CF, $FF, $73, $06, $F6, $C4, $10, $75, $EE, $F9,
    $C3, $F4, $EB, $FD, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $55, $AA, $B8, $00, $03, $8E, $C0, $66, $B9, $22, $11,
    $19, $68, $31, $FF, $66, $A1, $08, $00, $E8, $0C, $01, $26, $66, $3B, $0D, $0F,
    $85, $EB, $07, $81, $C7, $00, $02, $66, $A1, $0C, $00, $E8, $F9, $00, $26, $66,
    $3B, $0D, $0F, $85, $D8, $07, $26, $66, $8B, $16, $08, $00, $26, $66, $A1, $0C,
    $00, $26, $66, $3B, $06, $0C, $02, $75, $0A, $26, $66, $3B, $16, $08, $02, $0F,
    $84, $BB, $07, $72, $04, $81, $EF, $00, $02, $26, $66, $0F, $B7, $4D, $30, $C1,
    $E9, $09, $89, $0E, $2A, $00, $66, $B8, $80, $00, $00, $00, $66, $F7, $E1, $66,
    $A3, $34, $00, $66, $F7, $E0, $66, $A3, $38, $00, $0F, $BC, $C9, $88, $0E, $29,
    $00, $66, $A1, $08, $00, $66, $83, $C0, $08, $66, $01, $06, $04, $00, $83, $C7,
    $50, $BE, $00, $30, $E8, $AE, $00, $66, $B8, $80, $00, $00, $00, $E8, $B5, $00,
    $83, $C7, $24, $BE, $80, $30, $E8, $9C, $00, $66, $31, $C0, $E8, $A6, $00, $E8,
    $81, $01, $E8, $AD, $02, $80, $3E, $23, $00, $00, $0F, $84, $50, $07, $E8, $E7,
    $02, $E8, $2F, $03, $8A, $0E, $24, $00, $28, $0E, $23, $00, $0F, $84, $3E, $07,
    $F6, $06, $03, $00, $01, $74, $0A, $BD, $00, $31, $26, $66, $8B, $46, $1C, $EB,
    $27, $BE, $30, $01, $E8, $B1, $FE, $B7, $00, $B4, $03, $CD, $10, $FE, $CE, $88,
    $36, $27, $00, $88, $16, $28, $00, $51, $B9, $00, $20, $E8, $4C, $03, $E8, $53,
    $03, $E8, $13, $04, $59, $E8, $42, $03, $66, $C1, $E0, $07, $BE, $00, $30, $E8,
    $43, $00, $83, $C7, $24, $BE, $80, $30, $E8, $2A, $00, $E8, $73, $04, $E8, $F4,
    $04, $E8, $98, $06, $E9, $D5, $06, $66, $51, $BB, $01, $00, $E8, $A6, $FE, $66,
    $59, $73, $11, $26, $66, $89, $0D, $66, $31, $C0, $26, $66, $89, $45, $08, $26,
    $66, $89, $45, $0C, $C3, $56, $1E, $06, $1F, $87, $FE, $B9, $10, $00, $66, $F3,
    $A5, $A4, $1F, $5E, $C3, $31, $FF, $66, $31, $D2, $66, $0F, $B7, $0E, $2A, $00,
    $66, $C1, $E1, $09, $66, $F7, $F1, $52, $26, $8A, $4C, $40, $FE, $C9, $7D, $0F,
    $A3, $2C, $00, $89, $C3, $C1, $E3, $02, $26, $66, $8B, $00, $E9, $A2, $00, $75,
    $3A, $66, $31, $D2, $66, $8B, $0E, $34, $00, $66, $F7, $F1, $A3, $2C, $00, $89,
    $16, $2E, $00, $89, $C3, $C1, $E3, $02, $26, $66, $8B, $00, $8A, $0E, $29, $00,
    $66, $D3, $E0, $8B, $1E, $2A, $00, $E8, $1B, $FE, $8B, $1E, $2E, $00, $C1, $E3,
    $02, $26, $66, $8B, $01, $81, $C7, $00, $10, $EB, $66, $66, $31, $D2, $66, $8B,
    $0E, $38, $00, $66, $F7, $F1, $A3, $2C, $00, $89, $C3, $66, $89, $D0, $66, $31,
    $D2, $66, $8B, $0E, $34, $00, $66, $F7, $F1, $A3, $2E, $00, $89, $16, $30, $00,
    $C1, $E3, $02, $26, $66, $8B, $00, $8A, $0E, $29, $00, $66, $D3, $E0, $8B, $1E,
    $2A, $00, $E8, $D0, $FD, $8B, $1E, $2E, $00, $C1, $E3, $02, $26, $66, $8B, $01,
    $81, $C7, $00, $10, $8A, $0E, $29, $00, $66, $D3, $E0, $8B, $1E, $2A, $00, $E8,
    $B3, $FD, $8B, $1E, $30, $00, $C1, $E3, $02, $26, $66, $8B, $01, $81, $C7, $00,
    $10, $8A, $0E, $29, $00, $66, $D3, $E0, $8B, $1E, $2A, $00, $E8, $96, $FD, $5A,
    $01, $D7, $C3, $B8, $08, $00, $2B, $06, $2A, $00, $8A, $0E, $29, $00, $D3, $E8,
    $74, $5A, $89, $C1, $56, $57, $26, $0F, $B6, $5C, $40, $D1, $E3, $75, $04, $89,
    $F5, $EB, $04, $8D, $AD, $00, $F0, $8D, $B7, $2C, $00, $8B, $04, $C1, $E0, $02,
    $01, $C5, $51, $8B, $0E, $2A, $00, $C1, $E1, $09, $01, $CF, $FF, $04, $83, $C5,
    $04, $26, $66, $8B, $46, $00, $66, $83, $F8, $FF, $75, $0D, $57, $C1, $E9, $02,
    $66, $31, $C0, $66, $F3, $AB, $5F, $EB, $0E, $8A, $0E, $29, $00, $66, $D3, $E0,
    $8B, $1E, $2A, $00, $E8, $2E, $FD, $59, $E2, $C8, $5F, $5E, $F9, $C3, $55, $53,
    $81, $FB, $2C, $00, $74, $50, $83, $EB, $02, $8D, $BD, $00, $F0, $FF, $07, $81,
    $FB, $2C, $00, $75, $07, $BA, $10, $00, $89, $F5, $EB, $08, $8B, $16, $34, $00,
    $8D, $AD, $00, $F0, $3B, $17, $7F, $09, $E8, $D3, $FF, $73, $29, $C7, $07, $00,
    $00, $8B, $07, $C1, $E0, $02, $01, $C5, $26, $66, $8B, $46, $00, $66, $83, $F8,
    $FF, $74, $13, $8A, $0E, $29, $00, $66, $D3, $E0, $8B, $1E, $2A, $00, $E8, $D4,
    $FC, $8D, $BD, $00, $10, $F9, $5B, $5D, $C3, $26, $0F, $B6, $5C, $40, $D1, $E3,
    $75, $07, $BA, $10, $00, $89, $F5, $EB, $08, $8B, $16, $34, $00, $8D, $AD, $00,
    $F0, $8D, $9F, $2C, $00, $FF, $07, $3B, $17, $7F, $0C, $E8, $31, $00, $E8, $7D,
    $FF, $73, $27, $C7, $07, $00, $00, $8B, $07, $C1, $E0, $02, $01, $C5, $26, $66,
    $8B, $46, $00, $66, $83, $F8, $FF, $74, $11, $8A, $0E, $29, $00, $66, $D3, $E0,
    $8B, $1E, $2A, $00, $E8, $7E, $FC, $E9, $E9, $FE, $E8, $02, $00, $F8, $C3, $F6,
    $06, $03, $00, $01, $75, $0B, $53, $B0, $2E, $BB, $07, $00, $B4, $0E, $CD, $10,
    $5B, $C3, $BE, $00, $31, $87, $FE, $B9, $80, $00, $26, $66, $8B, $14, $66, $09,
    $D2, $74, $07, $26, $80, $7C, $04, $FF, $75, $05, $83, $C6, $20, $EB, $26, $83,
    $C6, $05, $51, $1E, $06, $1F, $B9, $1B, $00, $AC, $08, $C0, $75, $02, $B0, $20,
    $AA, $E2, $F6, $30, $C0, $AA, $66, $4A, $26, $66, $89, $15, $83, $C7, $08, $1F,
    $59, $FE, $06, $23, $00, $E2, $C3, $C3, $BE, $00, $30, $BD, $00, $31, $0F, $B6,
    $0E, $23, $00, $51, $26, $66, $8B, $46, $1C, $66, $C1, $E0, $07, $E8, $95, $FD,
    $26, $8B, $45, $20, $25, $00, $F0, $3D, $00, $80, $75, $0E, $26, $66, $83, $3D,
    $00, $74, $07, $26, $80, $7D, $64, $02, $7E, $08, $26, $F6, $56, $1B, $FE, $06,
    $24, $00, $26, $66, $8B, $45, $14, $26, $66, $89, $46, $20, $83, $C5, $24, $59,
    $E2, $C1, $C3, $BE, $00, $31, $0F, $B6, $0E, $23, $00, $51, $89, $F7, $26, $80,
    $7D, $1B, $00, $75, $39, $26, $80, $7C, $1B, $00, $75, $1A, $26, $66, $8B, $44,
    $20, $26, $66, $3B, $45, $20, $77, $26, $72, $0C, $26, $66, $8B, $44, $1C, $26,
    $66, $3B, $45, $1C, $73, $18, $BB, $20, $00, $26, $66, $FF, $30, $26, $66, $FF,
    $31, $26, $66, $8F, $00, $26, $66, $8F, $01, $83, $EB, $04, $7D, $EB, $83, $C7,
    $24, $E2, $BB, $83, $C6, $24, $59, $E2, $B2, $C3, $50, $BB, $00, $00, $B4, $01,
    $CD, $10, $58, $C3, $BD, $00, $31, $30, $F6, $8A, $16, $25, $00, $2A, $16, $26,
    $00, $0F, $B6, $0E, $23, $00, $80, $F9, $0A, $7E, $22, $B1, $0A, $08, $D2, $7D,
    $08, $FE, $0E, $26, $00, $FE, $C2, $EB, $0B, $80, $FA, $0A, $7C, $06, $FE, $06,
    $26, $00, $FE, $CA, $A0, $26, $00, $B4, $24, $F6, $E4, $01, $C5, $89, $C8, $28,
    $D0, $8A, $36, $27, $00, $8A, $16, $28, $00, $52, $5A, $FE, $C6, $52, $51, $50,
    $BB, $07, $00, $39, $C1, $75, $03, $C0, $CB, $04, $B9, $1B, $00, $B8, $00, $13,
    $CD, $10, $58, $59, $83, $C5, $24, $E2, $E1, $5A, $C3, $8A, $0E, $28, $00, $88,
    $CA, $80, $C2, $1B, $8A, $2E, $27, $00, $88, $EE, $FE, $C5, $80, $C6, $0A, $BB,
    $00, $07, $B8, $00, $06, $CD, $10, $BD, $00, $31, $0F, $B6, $06, $25, $00, $BA,
    $24, $00, $F7, $E2, $01, $C5, $8D, $76, $1A, $26, $80, $3C, $20, $75, $05, $4E,
    $39, $EE, $7F, $F5, $8D, $4C, $01, $29, $E9, $8A, $36, $27, $00, $FE, $C6, $8A,
    $16, $28, $00, $BB, $0F, $00, $B8, $01, $13, $CD, $10, $BE, $31, $01, $E8, $87,
    $FA, $26, $66, $8B, $46, $1C, $C3, $80, $3E, $23, $00, $01, $7E, $9D, $B9, $40,
    $00, $B4, $01, $CD, $16, $75, $13, $1E, $31, $C0, $8E, $D8, $A1, $6C, $04, $3B,
    $06, $6C, $04, $74, $FA, $1F, $E2, $E9, $EB, $81, $B4, $00, $CD, $16, $A0, $25,
    $00, $80, $FC, $48, $74, $18, $80, $FC, $50, $74, $19, $80, $FC, $47, $74, $1E,
    $80, $FC, $4F, $74, $20, $80, $FC, $1C, $0F, $84, $5F, $FF, $EB, $DC, $FE, $C8,
    $7C, $D8, $EB, $25, $FE, $C0, $3A, $06, $23, $00, $73, $CE, $EB, $1B, $30, $C0,
    $A2, $26, $00, $EB, $14, $A0, $23, $00, $FE, $C8, $88, $C4, $80, $EC, $0A, $7D,
    $02, $30, $E4, $88, $26, $26, $00, $EB, $00, $A2, $25, $00, $E8, $C5, $FE, $EB,
    $A9, $66, $31, $C0, $E8, $BE, $FB, $E8, $99, $FC, $66, $31, $DB, $66, $53, $E8,
    $2C, $00, $E8, $54, $FD, $66, $5B, $73, $09, $66, $81, $C3, $00, $10, $00, $00,
    $EB, $EB, $06, $B8, $40, $07, $8E, $C0, $66, $81, $C3, $FF, $8F, $10, $00, $66,
    $81, $E3, $00, $F0, $FF, $FF, $26, $66, $89, $1E, $00, $00, $07, $C3, $56, $BE,
    $50, $00, $B9, $00, $08, $8C, $C0, $06, $1E, $07, $66, $81, $FB, $00, $00, $02,
    $00, $9C, $66, $81, $C3, $00, $80, $00, $00, $C1, $E0, $04, $01, $F8, $89, $44,
    $12, $89, $5C, $1A, $66, $C1, $EB, $10, $88, $5C, $1C, $9D, $7D, $08, $B4, $87,
    $CD, $15, $0F, $82, $11, $02, $80, $44, $1C, $10, $B4, $87, $CD, $15, $0F, $82,
    $05, $02, $07, $5E, $C3, $B8, $00, $08, $8E, $C0, $31, $FF, $26, $66, $81, $3E,
    $00, $00, $7F, $45, $4C, $46, $75, $10, $66, $B8, $02, $B0, $AD, $1B, $B9, $00,
    $08, $66, $F2, $AF, $E3, $02, $EB, $01, $C3, $83, $EF, $04, $26, $66, $03, $45,
    $04, $26, $66, $03, $45, $08, $0F, $85, $BB, $01, $26, $66, $F7, $45, $04, $FC,
    $FF, $00, $00, $0F, $85, $AE, $01, $B8, $40, $07, $8E, $C0, $BE, $00, $0C, $31,
    $FF, $26, $83, $7C, $10, $02, $0F, $85, $9B, $01, $26, $83, $7C, $12, $03, $0F,
    $85, $92, $01, $26, $66, $8B, $44, $18, $26, $66, $89, $45, $04, $83, $C7, $08,
    $26, $8B, $4C, $2C, $09, $C9, $0F, $84, $7B, $01, $26, $8B, $54, $2A, $26, $8B,
    $44, $1C, $01, $C6, $26, $66, $83, $3C, $01, $75, $34, $26, $66, $8B, $44, $14,
    $26, $66, $89, $05, $26, $66, $8B, $44, $10, $26, $66, $89, $45, $04, $26, $66,
    $8B, $44, $04, $26, $66, $89, $45, $08, $26, $66, $8B, $44, $0C, $26, $66, $39,
    $06, $00, $00, $0F, $8F, $3E, $01, $26, $66, $89, $45, $0C, $83, $C7, $10, $01,
    $D6, $E2, $C1, $66, $31, $C0, $26, $66, $89, $05, $B8, $50, $07, $8E, $C0, $26,
    $66, $C7, $06, $00, $00, $03, $00, $00, $00, $26, $66, $C7, $06, $04, $00, $80,
    $02, $00, $00, $E8, $8E, $00, $26, $66, $A3, $08, $00, $66, $BA, $FF, $FF, $FF,
    $FF, $8A, $16, $11, $00, $26, $66, $89, $16, $0C, $00, $26, $66, $C7, $06, $10,
    $00, $00, $00, $00, $00, $BE, $33, $01, $E8, $7D, $F8, $E8, $86, $00, $FA, $66,
    $BB, $90, $00, $00, $00, $0F, $01, $17, $0F, $20, $C0, $83, $C8, $01, $0F, $22,
    $C0, $EA, $2F, $29, $08, $00, $66, $B8, $10, $00, $8E, $D8, $8E, $C0, $8E, $E0,
    $8E, $E8, $8E, $D0, $0F, $B7, $E4, $BB, $08, $74, $00, $00, $83, $3B, $00, $74,
    $21, $8B, $4B, $04, $8B, $73, $08, $81, $C6, $00, $80, $10, $00, $8B, $7B, $0C,
    $F3, $A4, $8B, $0B, $2B, $4B, $04, $7E, $04, $30, $C0, $F3, $AA, $83, $C3, $10,
    $EB, $DA, $B8, $02, $B0, $AD, $2B, $BB, $00, $75, $00, $00, $8B, $15, $04, $74,
    $00, $00, $FF, $E2, $B8, $01, $E8, $CD, $15, $72, $10, $66, $0F, $B7, $C0, $66,
    $0F, $B7, $DB, $66, $C1, $E3, $06, $66, $01, $D8, $C3, $B4, $88, $CD, $15, $66,
    $0F, $B7, $C0, $C3, $B8, $01, $24, $CD, $15, $73, $10, $E4, $92, $EB, $00, $EB,
    $00, $0C, $02, $24, $FE, $E6, $92, $EB, $00, $EB, $00, $C3, $B8, $00, $08, $8E,
    $C0, $31, $FF, $66, $B8, $EB, $7E, $FF, $00, $B9, $00, $20, $66, $F2, $AF, $E3,
    $2A, $83, $EF, $04, $26, $83, $7D, $0A, $03, $75, $21, $66, $B8, $00, $80, $10,
    $00, $01, $F8, $26, $66, $03, $45, $20, $26, $66, $89, $45, $28, $BE, $33, $01,
    $E8, $A5, $F7, $B8, $00, $08, $50, $31, $C0, $50, $CB, $C3, $BE, $04, $01, $E8,
    $96, $F7, $E9, $DC, $F7, $BE, $17, $01, $E8, $8D, $F7, $E9, $D3, $F7, $BE, $F1,
    $00, $E8, $84, $F7, $E9, $CA, $F7, $BE, $D3, $00, $E8, $7B, $F7, $E9, $C1, $F7);

const
  ESysEPERM = 1;    { Operation not permitted }
  ESysENOENT = 2;    { No such file or directory }
  ESysESRCH = 3;    { No such process }
  ESysEINTR = 4;    { Interrupted system call }
  ESysEIO = 5;    { I/O error }
  ESysENXIO = 6;    { No such device or address }
  ESysE2BIG = 7;    { Arg list too long }
  ESysENOEXEC = 8;    { Exec format error }
  ESysEBADF = 9;    { Bad file number }
  ESysECHILD = 10;   { No child processes }
  ESysEAGAIN = 11;   { Try again }
  ESysENOMEM = 12;   { Out of memory }
  ESysEACCES = 13;   { Permission denied }
  ESysEFAULT = 14;   { Bad address }
  ESysENOTBLK = 15;   { Block device required, NOT POSIX! }
  ESysEBUSY = 16;   { Device or resource busy }
  ESysEEXIST = 17;   { File exists }
  ESysEXDEV = 18;   { Cross-device link }
  ESysENODEV = 19;   { No such device }
  ESysENOTDIR = 20;   { Not a directory }
  ESysEISDIR = 21;   { Is a directory }
  ESysEINVAL = 22;   { Invalid argument }
  ESysENFILE = 23;   { File table overflow }
  ESysEMFILE = 24;   { Too many open files }
  ESysENOTTY = 25;   { Not a typewriter }
  ESysETXTBSY = 26;   { Text file busy. The new process was
                            a pure procedure (shared text) file which was
                            open for writing by another process, or file
                            which was open for writing by another process,
                            or while the pure procedure file was being
                            executed an open(2) call requested write access
                            requested write access.}
  ESysEFBIG = 27;   { File too large }
  ESysENOSPC = 28;   { No space left on device }
  ESysESPIPE = 29;   { Illegal seek }
  ESysEROFS = 30;   { Read-only file system }
  ESysEMLINK = 31;   { Too many links }
  ESysEPIPE = 32;   { Broken pipe }
  ESysEDOM = 33;   { Math argument out of domain of func }
  ESysERANGE = 34;   { Math result not representable }


  ESysEDEADLK = 35;   { Resource deadlock would occur }
  ESysENAMETOOLONG = 36;   { File name too long }
  ESysENOLCK = 37;   { No record locks available }
  ESysENOSYS = 38;   { Function not implemented }
  ESysENOTEMPTY = 39;      { Directory not empty }
  ESysELOOP = 40;   { Too many symbolic links encountered }
  ESysEWOULDBLOCK = ESysEAGAIN;   { Operation would block }
  ESysENOMSG = 42;   { No message of desired type }
  ESysEIDRM = 43;   { Identifier removed }
  ESysECHRNG = 44;   { Channel number out of range }
  ESysEL2NSYNC = 45;       { Level 2 not synchronized }
  ESysEL3HLT = 46;   { Level 3 halted }
  ESysEL3RST = 47;   { Level 3 reset }
  ESysELNRNG = 48;   { Link number out of range }
  ESysEUNATCH = 49;   { Protocol driver not attached }
  ESysENOCSI = 50;   { No CSI structure available }
  ESysEL2HLT = 51;   { Level 2 halted }
  ESysEBADE = 52;   { Invalid exchange }
  ESysEBADR = 53;   { Invalid request descriptor }
  ESysEXFULL = 54;   { Exchange full }
  ESysENOANO = 55;   { No anode }
  ESysEBADRQC = 56;   { Invalid request code }
  ESysEBADSLT = 57;   { Invalid slot }
  ESysEDEADLOCK = ESysEDEADLK; { number 58 is missing }
  ESysEBFONT = 59;   { Bad font file format }
  ESysENOSTR = 60;   { Device not a stream }
  ESysENODATA = 61;   { No data available }
  ESysETIME = 62;   { Timer expired }
  ESysENOSR = 63;   { Out of streams resources }
  ESysENONET = 64;   { Machine is not on the network }
  ESysENOPKG = 65;   { Package not installed }
  ESysEREMOTE = 66;   { Object is remote }
  ESysENOLINK = 67;   { Link has been severed }
  ESysEADV = 68;   { Advertise error }
  ESysESRMNT = 69;   { Srmount error }
  ESysECOMM = 70;   { Communication error on send }
  ESysEPROTO = 71;   { Protocol error }
  ESysEMULTIHOP = 72;      { Multihop attempted }
  ESysEDOTDOT = 73;   { RFS specific error }
  ESysEBADMSG = 74;   { Not a data message }
  ESysEOVERFLOW = 75;      { Value too large for defined data type }
  ESysENOTUNIQ = 76;       { Name not unique on network }
  ESysEBADFD = 77;   { File descriptor in bad state }
  ESysEREMCHG = 78;   { Remote address changed }
  ESysELIBACC = 79;   { Can not access a needed shared library }
  ESysELIBBAD = 80;   { Accessing a corrupted shared library }
  ESysELIBSCN = 81;   { .lib section in a.out corrupted }
  ESysELIBMAX = 82;   { Attempting to link in too many shared libraries }
  ESysELIBEXEC = 83;       { Cannot exec a shared library directly }
  ESysEILSEQ = 84;   { Illegal byte sequence }
  ESysERESTART = 85;       { Interrupted system call should be restarted }
  ESysESTRPIPE = 86;       { Streams pipe error }
  ESysEUSERS = 87;   { Too many users }
  ESysENOTSOCK = 88;       { Socket operation on non-socket }
  ESysEDESTADDRREQ = 89;   { Destination address required }
  ESysEMSGSIZE = 90;       { Message too long }
  ESysEPROTOTYPE = 91;     { Protocol wrong type for socket }
  ESysENOPROTOOPT = 92;    { Protocol not available }
  ESysEPROTONOSUPPORT = 93;        { Protocol not supported }
  ESysESOCKTNOSUPPORT = 94;        { Socket type not supported }
  ESysEOPNOTSUPP = 95;     { Operation not supported on transport endpoint }
  ESysEPFNOSUPPORT = 96;   { Protocol family not supported }
  ESysEAFNOSUPPORT = 97;   { Address family not supported by protocol }
  ESysEADDRINUSE = 98;     { Address already in use }
  ESysEADDRNOTAVAIL = 99;  { Cannot assign requested address }
  ESysENETDOWN = 100;      { Network is down }
  ESysENETUNREACH = 101;   { Network is unreachable }
  ESysENETRESET = 102;     { Network dropped connection because of reset }
  ESysECONNABORTED = 103;  { Software caused connection abort }
  ESysECONNRESET = 104;    { Connection reset by peer }
  ESysENOBUFS = 105;  { No buffer space available }
  ESysEISCONN = 106;  { Transport endpoint is already connected }
  ESysENOTCONN = 107;      { Transport endpoint is not connected }
  ESysESHUTDOWN = 108;     { Cannot send after transport endpoint shutdown }
  ESysETOOMANYREFS = 109;  { Too many references: cannot splice }
  ESysETIMEDOUT = 110;     { Connection timed out }
  ESysECONNREFUSED = 111;  { Connection refused }
  ESysEHOSTDOWN = 112;     { Host is down }
  ESysEHOSTUNREACH = 113;  { No route to host }
  ESysEALREADY = 114;      { Operation already in progress }
  ESysEINPROGRESS = 115;   { Operation now in progress }
  ESysESTALE = 116;  { Stale NFS file handle }
  ESysEUCLEAN = 117;  { Structure needs cleaning }
  ESysENOTNAM = 118;  { Not a XENIX named type file }
  ESysENAVAIL = 119;  { No XENIX semaphores available }
  ESysEISNAM = 120;  { Is a named type file }
  ESysEREMOTEIO = 121;     { Remote I/O error }
  ESysEDQUOT = 122;  { Quota exceeded }

{ List of missing system error numbers
  added using check_errno.sh script }
  ESysENOMEDIUM = 123;
  ESysEMEDIUMTYPE = 124;
  ESysECANCELED = 125;
  ESysENOKEY = 126;
  ESysEKEYEXPIRED = 127;
  ESysEKEYREVOKED = 128;
  ESysEKEYREJECTED = 129;
  ESysEOWNERDEAD = 130;
  ESysENOTRECOVERABLE = 131;
  ESysERFKILL = 132;

  { File types }
  S_IFMT = 61440; { type of file mask}
  S_IFIFO = 4096;  { named pipe (fifo)}
  S_IFCHR = 8192;  { character special}
  S_IFDIR = 16384; { directory }
  S_IFBLK = 24576; { block special}
  S_IFREG = 32768; { regular }
  S_IFLNK = 40960; { symbolic link }
  S_IFSOCK = 49152; { socket }
  S_ISUID = &4000;
  S_ISGID = &2000;
  S_ISVTX = &1000;

type
  TQNX6FS_INO_CKSUM = (NONE = 0,  (* don't checksum inodes (default) *)
    CRC32 = 1,  (* POSIX CRC32 checksum in inodes  *)
    F32 = 2  (* Fletcher-32 checksum in inodes  *)
    );

  PQNX6_RawDirEntry = ^TQNX6_RawDirEntry;

  TQNX6_RawDirEntry = packed record
    inode: dword;
    len: byte;
    Data: array[0..QNX6FS_DIR_SHORT_LEN - 1] of byte;
  end;
  TQNX6_ARawDirEntry = array of TQNX6_RawDirEntry;

  PQNX6_ShortNameEntry = ^TQNX6_ShortNameEntry;

  TQNX6_ShortNameEntry = packed record
    Name: array[0..QNX6FS_DIR_SHORT_LEN - 1] of UTF8Char;
  end;

  PQNX6_LongNameEntry = ^TQNX6_LongNameEntry;

  TQNX6_LongNameEntry = packed record
    dummy1: array[0..2] of byte;
    blkno: dword;
    cksum: dword;
    dummy2: array[0..15] of byte;
  end;

  PQNX6_CryptNameEntry = ^TQNX6_CryptNameEntry;

  TQNX6_CryptNameEntry = packed record
    iscrypt: bytebool;
    dummy1: array[0..2] of byte;
    blkno: dword;
    cksum: dword;
    Name: array[0..15] of byte;
  end;


type
  TQNX6_DB = array[0..QNX6FS_DIRECT_BLKS - 1] of dword;

  TQNX6_IInode = packed record
    size: qword;
    blocks: TQNX6_DB;
    indirect: byte;
    flags: byte;
    dummy: array[0..5] of byte;
  end;

  TQNX6_LongName = packed record
    len: word;
    Name: array[0..QNX6FS_NAME_MAX - 1] of UTF8Char;
  end;

  PQNX6_DInode = ^TQNX6_DInode;

  TQNX6_DInode = packed record
    size: qword;
    uid: dword;
    gid: dword;
    ftime: dword;
    mtime: dword;
    atime: dword;
    ctime: dword;
    mode: word;
    nlink: word;
    blocks: TQNX6_DB;
    indirect: byte;
    flags: byte;
    dummy1: array[0..1] of byte;
    crypt: dword;
    emode: dword;
    acl_iextra_plus_one: dword;
    (* One-greater than the iextra index where the ACL record starts.     *)
    (* Encoded this way so that QNX6FS_IE_INVALID_INDEX is stored as zero *)
    (* for backward compatibility with existing records that have no ACL. *)
    generation: dword;  (* inode generation (inode reuse bumps it up). *)
    dummy2: array[0..3] of byte;
    cksum32: dword;     (* 32-bit inode checksum *)
  end;


  TQNX6_SuperBlockRaw = packed record
    Magic: dword;
    CRC: dword;
    Serial: qword;
    ctime: dword;
    atime: dword;
    flags: dword;
    version: word;
    rsrvblks: word;
    volumeid: TGuid;
    blocksize: dword;
    num_inodes: dword;
    free_inodes: dword;
    num_blocks: dword;
    free_blocks: dword;
    allocgroup: dword;
    inodes: TQNX6_IInode;
    bitmap: TQNX6_IInode;
    lnames: TQNX6_IInode;
    s_iclaim: TQNX6_IInode;
    s_iextra: TQNX6_IInode;
    migrate_blocks: dword;
    scrub_block: dword;
    nsparse: dword;
    ino_cksum: byte; // TQNX6FS_INO_CKSUM
    dummy: array[0..26] of byte;
  end;

  TQNX6_Keylist = packed record
    version: dword;
    key: array[0..QNX6FS_DOMAIN_MAX] of dword;
  end;

  TQNX6_Domainkey = packed record
    random: array [0..QNX6FS_IEXTRA_SALT_SIZE - 1] of byte;
    version: dword;
    signature: dword;
    keyno: byte;
    reserved1: byte;
    reserved2: word;
    dummy: array [0..50 - 1] of byte;
    keytype: byte;
    keylen: byte;
    key: array [0..QNX6FS_IEXTRA_MAX_KEY_SIZE - 1] of byte;
  end;

  TQNX6_Filekey = packed record
    random: array [0..QNX6FS_IEXTRA_SALT_SIZE - 1] of byte;
    version: dword;
    flags: word;
    mode: word;
    size: qword;
    ino: qword;
    uid: dword;
    gid: dword;
    migration: qword;
    dummy: array[0..22 - 1] of byte;
    keytype: byte;
    keylen: byte;
    key: array [0..QNX6FS_IEXTRA_MAX_KEY_SIZE - 1] of byte;
  end;
