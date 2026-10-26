unit bbconst;

{$mode ObjFPC}{$H+}

interface

type
  TLoadCallback = procedure(i, s: integer);

const
  MAX_PACKET = $10000;

  BOOT_MODES: array[0..4] of string = (
    'RIM REINIT',
    'RIM-BootLoader',
    'RIM-RAMLoader',
    'RIM UPL',
    'RIM-BootNUKE'
  );

  CMD_PING              = $F000;
  CMD_READ_METRICS      = $F001;
  CMD_EXIT              = $F002;
  CMD_FRESHNESS_SEAL    = $F003;
  CMD_WRITE_RAM         = $F004;
  CMD_EXECUTE_RAM       = $F005;
  CMD_PASSWORD          = $F006;
  CMD_CHANGE_BPS        = $F007;
  CMD_DEVICE_NUKE       = $F008;
  CMD_WRITE_RAM_SETUP   = $F009;
  CMD_WRITE_RAM_VERIFY  = $F00A;
  CMD_READ_MODEL_CODE   = $F00B;
  CMD_X1                = $F00C;
  CMD_X2                = $F00D;

implementation

end.
