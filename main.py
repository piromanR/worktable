import psycopg2
import binascii

conn = psycopg2.connect('postgresql://postgres:11092001@localhost/workapp')
cursor = conn.cursor()
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS work (
        current_value_counter INTEGER,
        pressure_value numeric,
        status TEXT
    )
    """
)


hex_data = input("Введите массив байт в hex формате: ")

packets = [hex_data[i:i+8] for i in range(0, len(hex_data), 8)]

valid_packets = []
for packet in packets:
    try:
        if packet[0:2] != "80":
            continue

        counter = int(packet[2:4], 16)

        pressure = int(packet[4:8], 16) / 100.0

        valid_packets.append((counter, pressure))
    except:
        continue

for counter, pressure in valid_packets:
    query = "INSERT INTO work (current_value_counter, pressure_value, status) VALUES (%s, %s, '80')"
    cursor.execute(query, (counter, pressure))

conn.commit()

cursor.close()
conn.close()
