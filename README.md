
## Building

To build
```
cargo build --release
```
To run
```
./target/release/txn_verify | tee measurements.csv
```
That writes measurements out in csv format.
Figures can then be generated with
```
python3 generate_graph.py
```