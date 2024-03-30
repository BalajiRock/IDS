from datetime import datetime

def subtract_time(time1_str, time2_str):

  try:
    time1 = datetime.strptime(time1_str, "%m/%d/%Y %H:%M:%S.%f")
    time2 = datetime.strptime(time2_str, "%m/%d/%Y %H:%M:%S.%f")

    difference = time1 - time2
    return difference.total_seconds()
  except ValueError:
    print("Invalid time format. Please use 'MM/DD/YYYY HH:MM:SS.FFF'.")
    return None

# Example usage
time1_str = "06/03/2024 00:23:33.368500"
time2_str = "06/03/2024 00:23:33.368700"

difference = subtract_time(time1_str, time2_str)

if difference is not None:
  print(f"The difference between the two times is {difference:.10f} seconds.")
