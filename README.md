[![MIT License][license-image]][license-url]

# Simple Hashicorp Vault policy path generator


## Usage

```sh
cat ./policy.yml | ./vaultPG.py
```

Source

```yaml
#  vim: set et fenc=utf-8 ff=unix sts=2 sw=2 ts=2
# policy
#   c = create
#   r = read
#   u = update
#   d = delete
#   l = list
#   s = sudo
#   x = deny
#   UPPERCASE = recurse mode
path:
  - path: "secret/data/dc1/shared*"
    capabilities: Lcrud
  - path: "secret/data/dc1/read"
    capabilities: Lr
```

Policy

```json
{
  "path": {
    "secret": {
      "capabilities": [
        "list"
      ]
    },
    "secret/data": {
      "capabilities": [
        "list"
      ]
    },
    "secret/data/dc1": {
      "capabilities": [
        "list"
      ]
    },
    "secret/data/dc1/read": {
      "capabilities": [
        "read",
        "list"
      ]
    },
    "secret/data/dc1/shared*": {
      "capabilities": [
        "delete",
        "create",
        "read",
        "update",
        "list"
      ]
    }
  }
}
```

## License

[![MIT License][license-image]][license-url]

## Author

- [Blinov Evgeniy](mailto:evgeniy_blinov@mail.ru) ([http://blinov.in.ua/](http://blinov.in.ua/))

[license-image]: http://img.shields.io/badge/license-MIT-blue.svg?style=flat
[license-url]: LICENSE
