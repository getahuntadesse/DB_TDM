import time
import psutil
import json
import os
from datetime import datetime, timezone

class CPUMonitor:
    def __init__(self, user, current_date_time):
        self.user = user
        self.interval = 1  # Monitoring interval in seconds
        self.current_date_time = current_date_time
        self.data_file = self.generate_filename()

    def generate_filename(self):
        """Generates a filename based on the provided date, time, and username."""
        date_part = self.current_date_time[:10]
        time_part = self.current_date_time[11:13] + self.current_date_time[14:16] + self.current_date_time[17:19]
        filename = f"cpu_stress_data_{date_part}_{time_part}_{self.user}.json"
        return filename

    def measure_cpu_stress(self):
        """Measures CPU stress level and logs it to a file."""
        try:
            cpu_usage = psutil.cpu_percent(interval=self.interval)
            memory_usage = psutil.virtual_memory().percent
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            data = {
                "timestamp": timestamp,
                "cpu_usage": cpu_usage,
                "memory_usage": memory_usage,
                "user": self.user
            }

            self.log_data_to_file(data)

            print(f"CPU Usage: {cpu_usage}%, Memory Usage: {memory_usage}% (Logged to {self.data_file})")

        except Exception as e:
            print(f"Error measuring CPU stress: {e}")

    def log_data_to_file(self, data):
        """Logs the CPU stress data to a JSON file."""
        try:
            # Ensure the directory exists
            directory = os.path.dirname(self.data_file)
            if directory and not os.path.exists(directory):
                os.makedirs(directory)

            with open(self.data_file, "a") as f:
                json.dump(data, f)
                f.write("\n")  # Add a newline for easier reading

        except IOError as e:
            print(f"Error writing to file: {e}")

    def run(self):
        """Runs the CPU monitoring loop."""
        try:
            while True:
                self.measure_cpu_stress()
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print("Monitoring stopped.")

if __name__ == "__main__":
    current_date_time = "2025-02-18 10:22:10"  # From user input
    user = "getahuntadesse"  # From user input
    monitor = CPUMonitor(user, current_date_time)
    monitor.run()