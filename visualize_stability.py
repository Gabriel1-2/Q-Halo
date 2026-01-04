
import matplotlib.pyplot as plt
import csv
import re
import sys
from scipy.stats import linregress

def parse_data(filename):
    steps = []
    weights = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            # Match strictly "number,number"
            if re.match(r'^\d+,\d+$', line):
                parts = line.split(',')
                steps.append(int(parts[0]))
                weights.append(int(parts[1]))
    return steps, weights

def main():
    print("Parsing data...")
    steps, weights = parse_data('raw_output.txt')
    
    if not steps:
        print("No CSV data found in raw_output.txt")
        sys.exit(1)
        
    print(f"Found {len(steps)} data points.")

    # Plot
    plt.figure(figsize=(10, 6))
    plt.plot(steps, weights, label='Hamming Weight (u)', color='blue', alpha=0.6, linewidth=0.5)
    plt.scatter(steps, weights, s=2, color='blue', alpha=0.5) # points

    # Trend Line
    slope, intercept, r_value, p_value, std_err = linregress(steps, weights)
    print(f"Slope: {slope}")
    print(f"Intercept: {intercept}")
    
    trend_y = [slope * x + intercept for x in steps]
    plt.plot(steps, trend_y, color='red', linewidth=2, label=f'Trend (slope={slope:.5f})')

    plt.title('Stability of Slack Variable u (Recursion Error)')
    plt.xlabel('Recursion Step')
    plt.ylabel('Hamming Weight')
    plt.legend()
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)

    # Hypothesis Check
    if abs(slope) < 0.01:
        plt.text(len(steps)/2, max(weights) + 1, "CONCLUSION: STABLE RECURSION", 
                 fontsize=12, color='green', ha='center', fontweight='bold')
        print("CONCLUSION: STABLE RECURSION")
    else:
         plt.text(len(steps)/2, max(weights) + 1, "WARNING: ERROR GROWTH DETECTED", 
                 fontsize=12, color='red', ha='center', fontweight='bold')
         print("WARNING: ERROR GROWTH DETECTED")

    output_file = 'error_stability_proof.png'
    plt.savefig(output_file, dpi=300)
    print(f"Saved chart to {output_file}")

if __name__ == "__main__":
    main()
