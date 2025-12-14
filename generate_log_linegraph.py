import pandas as pd
import matplotlib.pyplot as plt

def generate_log_linegraph(file_path):
    # 1. Load Data
    try:
        df = pd.read_csv(file_path)
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return

    # 2. Calculate Throughput
    # Throughput (txns/s) = (num_txns * 1000) / elapsed_ms
    df['throughput'] = (df['num_txns'] * 1000) / df['elapsed_ms']

    # Ensure verified is boolean
    df['verified'] = df['verified'].astype(bool)

    # 3. Plotting
    plt.figure(figsize=(10, 6))

    # Separate data
    df_true = df[df['verified'] == True]
    df_false = df[df['verified'] == False]

    # Plot lines
    plt.plot(df_true['num_keys'], df_true['throughput'],
             label='Verified = True', marker='o', linestyle='-')
    plt.plot(df_false['num_keys'], df_false['throughput'],
             label='Verified = False', marker='s', linestyle='--')

    # --- SET LOG SCALE ---
    plt.yscale('log')

    # Labels and Title
    plt.xlabel('Number of Keys')
    plt.ylabel('Throughput (txns/sec) - Log Scale')
    plt.title('Throughput vs. Number of Keys')
    plt.legend(title='Verified')

    # Grid lines are helpful for reading log scales
    plt.grid(True, which="both", ls="-", alpha=0.5)
    plt.tight_layout()

    # Save
    output_filename = 'linegraph_log.png'
    plt.savefig(output_filename)
    print(f"Graph saved to {output_filename}")

if __name__ == "__main__":
    generate_log_linegraph('measurements.csv')
