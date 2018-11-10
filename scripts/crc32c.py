def calc_crc32c_table(polynomial):
  crc32c_table = [0 for _ in range(0, 256)]

  checksum = 0

  for table_index in range(0, 256):
    checksum = table_index;

    for bit_iterator in range(0, 8):
      if checksum & 1:
        checksum = polynomial ^ ( checksum >> 1 );
      else:
        checksum = checksum >> 1;

    crc32c_table[table_index] = checksum;

  return crc32c_table

def calc_crc32c(initial_value, data):
  crc32c_table = calc_crc32c_table(0x82f63b78)

  checksum = initial_value;

  for byte_value in bytearray(data):
    table_index = (checksum ^ byte_value) & 0x000000ff;

    checksum = crc32c_table[table_index] ^ (checksum >> 8);

  return checksum
