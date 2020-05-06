## Description
Please include a summary of the change and which issue is fixed. Please also include relevant motivation and context. List any dependencies that are required for this change.

Fixes # (issue)

## Type of change
Please delete options that are not relevant.

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] This change requires a documentation update

## How Has This Been Tested
Please describe the tests that you ran to verify your changes. Provide instructions so we can reproduce. Please also list any relevant details for your test configuration

- [ ] Test A
- [ ] Test B

#### Test Configuration
<details><summary>Clich Here to Expand</summary>

```json
{
    "protocols": {
        "http": {
            "transport": "tcp",
            "from_port": 80,
            "to_port": 80
        },
        "https": {
            "transport": "tcp",
            "from_port": 443,
            "to_port": 443
        },
        "ssh": {
            "transport": "tcp",
            "from_port": 22,
            "to_port": 22
        },
        "rdp": {
            "transport": "tcp",
            "from_port": 3389,
            "to_port": 3389
        }
    },
    "rules": [
        {
            "cidr": "34.226.14.13/32",
            "note": "Primary VPN"
        },
        {
            "cidr": "52.15.127.128/27",
            "note": "UK Office"
        },
        {
            "cidr": "35.158.136.0/22",
            "note": "US Office"
        },
        {
            "cidr": "52.57.254.0/29",
            "note": "IL Office"
        },
        {
            "cidr": "13.54.63.128/32",
            "note": "Backup VPN"
        }
    ]
}
```

</details>

# Checklist
- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
