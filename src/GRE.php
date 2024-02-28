<?php

namespace GRE;
use function pack, unpack;
use function substr;
use function count, array_sum;

const ETHER_TYPE_IPv4 = 0x0800;
const ETHER_TYPE_IPv6 = 0x86DD;

/**
 * GRE Header struct
 */
class header {
  public function __construct(
    public bool   $checksum_present = false,            // Checksum Present (bit 0)
    public bool   $key_present      = false,            // Key Present (bit 2)
    public bool   $sequence_present = false,            // Sequence Number Present (bit 3)
    public int    $reserved0        = 0,                // Reserved0 (bits 4-12)
    public int    $version_number   = 0,                // Version Number (bits 13-15)
    public int    $protocol_type    = ETHER_TYPE_IPv4,  // Protocol Type (2 octets)
    public int    $checksum         = 0x0000,           // Checksum (2 octets)
    public int    $reserved1        = 0x0000,           // Reserved 1 (2 octets)
    public int    $key              = 0x00000000,       // Key Field (4 octets)
    public int    $sequence_number  = 0x00000000,       // Sequence Number (4 octets)
    public string $payload          = ""                // payload packet (in binary)
  ) {}
}

/**
 * @param header $header
 * @return string
 */
function pack_header(header $header): string {

  $checksum_present = (int)$header->checksum_present;
  $key_present      = (int)$header->key_present;
  $sequence_present = (int)$header->sequence_present;
  $reserved0        = $header->reserved0;
  $version_number   = $header->version_number;

  $header_flags =
    ($checksum_present << 15) | ($key_present << 13) |
    ($sequence_present << 12) | ($reserved0   << 3)  |
    $version_number;

  $packed = pack("n2", $header_flags, $header->protocol_type);

  if ($header->checksum_present) {
    $header->checksum = checksum($header);
    $packed .= pack("n2", $header->checksum, $header->reserved1);
  }
  if ($header->key_present) {
    $packed .= pack("N", $header->key);
  }
  if ($header->sequence_present) {
    $packed .= pack("N", $header->sequence_number);
  }

  return $packed . $header->payload;

}

/**
 * @param string $header
 * @return header
 */
function unpack_header(string $header): header {

  $octets = unpack("C*", $header);

  $checksum_present = ($octets[1] & 0x80) >> 7;
  $key_present      = ($octets[1] & 0x20) >> 5;
  $sequence_present = ($octets[1] & 0x10) >> 4;
  $reserved0        = (($octets[1] & 0x0f) << 5) | ($octets[2] >> 3);
  $version_number   = ($octets[2] & 0x07);
  $protocol_type    = ($octets[3] << 8) | $octets[4];

  $unpacked = new header(
    $checksum_present,
    $key_present,
    $sequence_present,
    $reserved0,
    $version_number,
    $protocol_type
  );

  $offset = 4;

  if ($checksum_present) {
    $unpacked->checksum  = ($octets[++$offset] << 8) | ($octets[++$offset]);
    $unpacked->reserved1 = ($octets[++$offset] << 8) | ($octets[++$offset]);
  }

  if ($key_present) {
    $unpacked->key =
      ($octets[++$offset] << 24) | ($octets[++$offset] << 16) |
      ($octets[++$offset] << 8)  | ($octets[++$offset]);
  }

  if ($sequence_present) {
    $unpacked->sequence_number =
      ($octets[++$offset] << 24) | ($octets[++$offset] << 16) |
      ($octets[++$offset] << 8)  | ($octets[++$offset]);
  }

  $unpacked->payload = substr($header, $offset);

  return $unpacked;

}

/**
 * @param header $header
 * @return int
 */
function checksum(header $header): int {

  $words    = [];  // uint16_t[]
  $offset   = 0;   // int
  $checksum = 0x0000;

  $words[$offset] =
    ($header->checksum_present << 15) | ($header->key_present << 13) |
    ($header->sequence_present << 12) | ($header->reserved0   << 3)  |
    $header->version_number;
  $words[++$offset] = $header->protocol_type;
  $words[++$offset] = $checksum;
  $words[++$offset] = $header->reserved1;

  if ($header->key_present) {
    $words[++$offset] = ($header->key >> 16) & 0xffff;
    $words[++$offset] = $header->key & 0xffff;
  }

  if ($header->sequence_present) {
    $words[++$offset] = ($header->sequence_number >> 16) & 0xffff;
    $words[++$offset] = $header->sequence_number & 0xffff;
  }

  $payload_octets = unpack("C*", $header->payload);

  for ($i = 1; $i <= count($payload_octets); $i++) {
    $words[++$offset] = ($payload_octets[$i] << 8) | @$payload_octets[++$i] ?? 0x00;
  }

  $checksum = array_sum($words);
  while ($checksum >> 16) {
    $checksum = ($checksum >> 16) + ($checksum & 0xffff);
  }

  return ~$checksum;

}