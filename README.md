# ech-check

Supporting scripts for checking ECH and Kyber adoption.

## Usage

First, the program requires you to provide domains to check. This can either be a list of domains used as arguments to the program or a path to a CSV file using `--domains`. In that case, the path points to a CSV file with a column called `domain` containing the domains to check. This format is compatible with the [Cloudflare Radar](https://radar.cloudflare.com/) export format. After creating this file, you can run the program as follows:

```bash
go run . crypto.cloudflare.com
```
