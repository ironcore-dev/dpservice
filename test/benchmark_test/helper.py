import re

# string processing functions


def remove_last_empty_line(output):
	lines = output.splitlines()
	if lines and lines[-1] == '':
		lines.pop()
	return '\n'.join(lines)

# result checking functions


def result_checking_ping_failed(result, query):
	return query in result


def result_checking_throughput_higher_than(result, minimum_throughput):
	# Regex to find the "Average Throughput (Gbits/sec):" followed by a number
	match = re.search(
		r"Average Throughput \(Gbits/sec\):\s+(\d+\.\d+)", result)
	if match:
		# Convert the found string to a float
		average_throughput = float(match.group(1))
		# Compare it to the minimum threshold
		if average_throughput >= minimum_throughput:
			return True
		else:
			return False
	else:
		# If no matching throughput is found, handle it accordingly
		print("No average throughput found in the result.")
		return False
