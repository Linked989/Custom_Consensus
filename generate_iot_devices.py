import uuid
import random
import json
from datetime import datetime

# Expanded lists of adjectives and nouns
ADJECTIVES = [
    "fuzzy", "bright", "silent", "crispy", "cool", "spicy", "gentle", "wild", "lazy", "smart",
    "breezy", "cheerful", "mellow", "noisy", "brave", "shy", "sassy", "quirky", "swift", "graceful"
]

NOUNS = [
    "pepper", "applespice", "cinnamon", "lemon", "fig", "mint", "hazel", "cherry", "nutmeg", "juniper",
    "thyme", "clover", "sage", "paprika", "basil", "lavender", "marjoram", "rosemary", "vanilla", "poppy"
]

# Sensor types and base value generators
SENSOR_TYPES = {
    "temperature": lambda: round(random.uniform(18.0, 26.0), 2),              # °C
    "humidity": lambda: round(random.uniform(35.0, 60.0), 2),                 # %
    "air_quality": lambda: random.randint(50, 150),                          # AQI
    "co2_level": lambda: round(random.uniform(400.0, 1000.0), 1),            # ppm
    "heart_rate": lambda: random.randint(60, 90),                            # bpm
    "blood_pressure_systolic": lambda: random.randint(110, 130),            # mmHg
    "blood_pressure_diastolic": lambda: random.randint(70, 85),             # mmHg
    "light_level": lambda: round(random.uniform(100.0, 800.0), 1),           # lux
    "sound_level": lambda: round(random.uniform(30.0, 70.0), 1),             # dB
    "motion": lambda: random.choice([0, 1]),                                 # Boolean
    "glucose_level": lambda: round(random.uniform(70.0, 140.0), 1),          # mg/dL
    "oxygen_saturation": lambda: round(random.uniform(95.0, 100.0), 1)       # %
}

def generate_smooth_series(base_value, variation=0.05, count=10, round_to=2):
    """Generates a list of values with smooth variations."""
    series = [base_value]
    for _ in range(count - 1):
        delta = base_value * variation
        next_val = random.uniform(series[-1] - delta, series[-1] + delta)
        series.append(round(max(0, next_val), round_to))  # avoid negatives
    return series

def generate_device_name(existing_names):
    """Generates a unique device name."""
    while True:
        name_base = f"{random.choice(ADJECTIVES)}-{random.choice(NOUNS)}"
        suffix = f"{random.randint(1000, 9999)}"
        full_name = f"{name_base}-{suffix}"
        if full_name not in existing_names:
            return full_name

def generate_iot_devices(count):
    devices = []
    used_names = set()

    for _ in range(count):
        name = generate_device_name(used_names)
        used_names.add(name)

        sensor_type = random.choice(list(SENSOR_TYPES.keys()))
        base = SENSOR_TYPES[sensor_type]()
        reading_count = random.randint(15, 20)  # <- variable-length sensor value list

        # Determine rounding
        if isinstance(base, int):
            readings = generate_smooth_series(base, variation=0.05, count=reading_count, round_to=0)
        elif sensor_type == "motion":
            readings = [random.choice([0, 1]) for _ in range(reading_count)]
        else:
            readings = generate_smooth_series(base, variation=0.05, count=reading_count, round_to=2)

        device = {
            "device_id": str(uuid.uuid4()),
            "device_name": name,
            "sensor_type": sensor_type,
            "sensor_value": readings,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        devices.append(device)

    return devices

def save_to_json(devices, filename="iot_devices.json"):
    with open(filename, "w") as f:
        json.dump(devices, f, indent=4)

if __name__ == "__main__":
    try:
        num = int(input("Enter number of IoT devices to generate: "))
        devices = generate_iot_devices(num)
        save_to_json(devices)
        print(f"{num} IoT devices saved to 'iot_devices.json'")
    except ValueError:
        print("Please enter a valid integer.")
