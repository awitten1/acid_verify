import pandas as pd
import matplotlib.pyplot as plt

def generate_throughput_linegraph(file_path):
    """
    Reads a CSV, calculates throughput, and generates a line graph
    with throughput vs. num_keys, separated by the 'verified' status.

    Args:
        file_path (str): The path to the input CSV file.
    """
    try:
        # 1. Load the data
        df = pd.read_csv(file_path)

        # 2. Calculate Throughput
        # Throughput (txns/s) = num_txns / (elapsed_ms / 1000)
        # = (num_txns * 1000) / elapsed_ms
        df['throughput'] = (df['num_txns'] * 1000) / df['elapsed_ms']

        # Convert 'verified' column to boolean for explicit filtering, if not already
        df['verified'] = df['verified'].astype(bool)

        # 3. Generate Line Graph
        plt.figure(figsize=(10, 6))

        # Filter for the two lines
        df_true = df[df['verified'] == True]
        df_false = df[df['verified'] == False]

        # Plot the lines
        # 'o' marker is used to clearly show the individual data points
        plt.plot(df_true['num_keys'], df_true['throughput'],
                 label='Verified = True', marker='o')
        plt.plot(df_false['num_keys'], df_false['throughput'],
                 label='Verified = False', marker='o')

        # Set labels and title
        plt.xlabel('Number of Keys (num_keys)')
        plt.ylabel('Throughput (transactions/second)')
        plt.title('Throughput vs. Number of Keys by Verification Status')
        plt.legend(title='Verified')
        plt.grid(True)
        plt.tight_layout()

        # Save the plot
        plot_filename = 'linegraph.png'
        plt.savefig(plot_filename)
        print(f"Line graph saved to {plot_filename}")

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example usage (assuming 'measurements.csv' is in the same directory)
generate_throughput_linegraph('measurements.csv')
