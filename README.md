# ech-check

Supporting scripts for checking ECH adoption.

## Usage

First, the program requires you to provide a list of domains to check. This is a csv file with a column called `domain` containing the domains to check. This format is compatible with the [Cloudflare Radar](https://radar.cloudflare.com/) export format. After creating this file, you can run the program as follows:

```bash
go run . domains.csv
```

The program will output a csv file with the results of the checks to `./out.csv`.