from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

class PublicKeys:
    
    pubkey_dictionary = {
        "gon": "AAAAB3NzaC1yc2EAAAADAQABAAABgQC++PTjonnxAOpbHGl3tk7sZcyuhtIuqgqQpUjPRyyUosbDvgFOjRssuPy9kvo2/Gl5U3bjxv0iwark2t6NpGhK9mtweJvSkxWZwQSAxUiNikK48TxFlOhQuKRR9OY1ZkF+FiWoEGTWSaaAKZpNjGuFoUgwMAKC2zP1yu+SkIzW6wx42UHdVSkDCbHpUBHf7hvIgzZgBBSuceVSc7bUAYk1sj+drkZVY64ChYleFnrRnm/6RNXCXzvNDuyFi1TOi+36AipQsYkRDywd8WpFYqBHnizyLEzsBlkvAv6geKprJ2RyNA6EBekv7EQBRgQQS0YXqX9CeNcHG8ng9YNuwApWlb+NWPAL2SIrcWkz8S0oU3yg6axPF3iLr3zdAhKdNW8qFylybfMEgnkxup1/UAOsyH53WevOnqzrcy7GWn5iYu22XdQjAOR8z+7wtY/K7Kh0fm0iUAE9mXpuKETJ9JVIydEiycEqIEqHR3OMGzkaN+grKCYV3CVEAyUjLidlvEc=",
    "jmp": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7xX0SKsM3y95F2xORZGPbwMLRHNrv7odUfJrdRvIuvkOT6XclnVeB56sBcIY2OEsiIEwu2Cv3CgCfq61878UVpa6cZxx36SNeUDWgE5lm+dB55K/WIPytQAe761ICDXC/I/c/HDsUt0TOZZATk4tjXiBM28q1MD3f/euaSawpcUAeYpCkYcsTGjM+5QkJ8Tu7o86ZoixKeg6qXaJ+xCtOGmmyYXFJ5iIXILyBisnoJ+CiDF+7OkVx5PqyVjWCkdbHpi4frDoH8tBLCPqZBjjsSvEtDQm4rlLsTiAody57Jw9EpG7KB0wfsEZyuktKXq8rp+qOFpwRyDygg4SBTaoywIDAQAB",
    "avp": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDQGbdkx5x7aNewSDt7HTDmHndXtTQp+9F99Q/t/2/s7a32OyR6dDRBUO2T0iF4MwRgddT8V4/7v4MvotCYNRGkSetzVHNKkZiCsD2nOZHIFruhlv/2kqRTohBfDblyhBvPbFQmxnECEo758yZnlHYTSmHDMDMhul2WXqA58jO9MVam/k8opb2hpbS8uQlPWbVtOOJ6B8FK/FD0rolBSusz//Y89VQik5A9r5oGV+I7nws6fyvwyzXvASSMOEpbONVhziHoKZacpx7AxDiytpvOaChbCBCXOY+B9KHfJD7aZuJYKaYagJYrngKVWXVYwVOecqi6k04t9943WPjsjkuPsHXJkFI0TJrMNb4nO5sDNE3ZR8sOrfI+xW/GkkNWYwY6oCUymYLVcdi2n4O8hYUkiB1NW/DpU0Fvc889VC/o+SLi+2ZDO1CHUV9rF/UQL6Y4O4qJn9kOX8d/eR+3BZs/phU+81uBqObxcVo2o32YkCL/4v8lvscS0LFpp5irVfE=",
    "pbc": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDIgZC1cu1ZYN4+/ItnB7nXbcE1gcCl5ueNwmFg+lRsTJJy1dryxNJGiX2bq9vIu/1w5zVLJ00tOlBsbrQyNDjX9HznCPfplb/TLxxDoC7LjYIL9vyHTxjtbFg2N9aG98dThBLNJlsXP7gsJrtDl7mZJ9Ikag9s+5uoZt0qD6fbJoAtiX2FudsLBVcj0be/SLeQ4NrEW+HiqWfw7Qw+XgpQB/59mPXGBicKImjCr9jZKCcZbXQiC/FRrAbpesWIxc8gkmKEanfQPqzflirT5Z4s7H5/ZSYlov9e0B/17YLU3S/9lJ+8ZSbArBjQljsjvsCpEJDZa8w1xea1sUwVcMJXaneAWmPuz6YKVMHsaoe6UU7c6OiAH90ko/Rv7qSJuBmuzr5unMVLB6uhSohKej1wf8ny8NLnqlmaRXUDfAmfb/RxiFep8FBho+MXQE4XO3bUmB1myW05l8F6DBinkTIo2YKwd6a2eFE/QOevLdryAYS44G8VWWoZRC5tQqlUq4c=",
    "abh": "AAAAB3NzaC1yc2EAAAADAQABAAABgQCv1J5tMa5Y8oispR6F17PdguYPBLpfhpXCw4wecTtaugD6VQetJ+IQBcQ3uaV1bxkxalJeBee1Ya4Plh16pq03Nos4HO9OheiaR3GPMRAvbIf6YV0MCrj2fHdC3SzILT1DgjfZDYvpO3fZCxvLfEpYeYMCYnAaI3UFTP3d4licuk35WfvshV/CHW0S1Pv2qByTC7FvB/GDl95hBH2kJY6LAuGVx1dv/gG5I5vB5r+HnRbTV7IN3+P9/j2WM85/qCyF9yBAlhI0x3aH9bcI8dFgfWlzbhBx2abXmMtF1yn1YAyvXcGxlRh8RC1vsPoV5EVDDmoRdmAf0NhbWyz4qvaRwvwtAjk5E/UaVi5WYuviIGEnmPJain4NtTO/3OrUYx9s1sZrtVaRumAu62DFgT37HdW+JSXMWzzbpvg28CquMRFXtVBroFBICHVrNKN2Ra1fmGoWxYGp0wXizvN/YfMU8fEoRQ8v3x6Rc8312Bez9zARBkY6aknK7+P28PduIXc=",
    "nuci": "AAAAB3NzaC1yc2EAAAADAQABAAABAQD1AMNWu9KalxGSmOSFmSmk2QvU8rdVvI9KLvbS3OrSeMlYVEV1+SjsgraGQ5C0o+nJiQSWfhOTfAYXEf+DotchXU2Q/gzXIUMTBudxr77mNKavybROVxqukxefc0P3QiUQxrDd7R7xEhyzurK/bkmCvqhsjVKR19jpPrBvpR+4ISo7qZEH3PJ+n2xEF1gK7m9WUx4P0GgJ7/mt8YcXQqId0qimN1Ulbc00FdsF7qKhjd37MWbKov5WB8Zi5xBAuw7F2IYBDWY4JCWm8Gd3hhg57hGUy0olfdMEFf811UEnIv7PYdDaXLUh+laeOcceOrkpyp4RPSHymyHzSQhVT9al",
    "emsi": "AAAAB3NzaC1yc2EAAAADAQABAAABgQCzdEDBooTMH8H01uin7t9bfQfpb/WpUZYtoHIUWBxm061RIw6APFFf25nfK9yR27FrAZaaNGZxcuTrgDF/1n9X1GufMDn3OfCdUSqlQSgYjk7ekMidNds1IZ/rI8YxNUyJIAJkbNp9oIG0vbJtr25xaSjA5MI7HPzlVl51D6Wzo94eJblclzJVJaLMjgM/WuFjEuyBREeUM3INzskVsVuQsakpI1XeM2TdLxQdjevnr9E3M8VRCOaDImckjXFWoQLYATilRrUlcvv2IQ4rpAKalOkRBAxhRkq75F0C4AT4kRQ8pioaqvmjhDhVwVt9Lt5Pt7HDu+4Sy/SjSoFI+HgaWaR+Delm6Ip2yNGY56HWRvtF1ihUQldW3HiA0aS6lKrZY/ZDg9N034cTapywWmA3uyUky+SGNQXb1PLx3YM3wrQFToZVA3YERHEigfRU7oN4DTPW19EL+VMWpYnYXRHwEQSqsfyrMEVSrHGuNTHCr36xr3Gr9m5xOzIKKzYZfA0=",
    "dpm": "AAAAB3NzaC1yc2EAAAADAQABAAABAQC/AfzLR76kKJbYEgks960kHfaABQHEva7aaEH5pUeG/5EoSj1b+Q0vBzeJkF0Pdcscs00kSBPQSJ91bfzoIpeLhU7hHK/CAbTok /5vUmTdmmU7KbJzFoJGFTTzpGTdsQ5/YNvKUtqNlm3a0DiB9Ampyfv8FZWNK5r6I4xdeIhAUgPDwNWKPMgWfd4SFs6R1gePG2FfPR5MEZgPcw3+fZgUOhMBhwhNFzqlz/rDVm4FPU1gsJscT6p1CONuuDOLM82eqjH95WEbCxUV2CTc2ju+whO0Ub02wh80lBc9N+hDGbWb0mqo1lEMorkDJmhA6l7P8sA7rQcFtpQdEdT9OZVr",
    "rdm": "AAAAB3NzaC1yc2EAAAADAQABAAABAQC19bVazMXGwKZGbTjBlaV9m9aJuKmfxVrKSUjai3sSfnshViqHwoCIxOnjXNdOQec5rWoi2dAMXlnigx099aKysZD0mGQHa1jFoCbYylsgbh2lDJmurElbGfd8UTEHXEFf+pvw2H+pVS5GSi+2r3RBtp675v16FFgMsv7+rhKHpBV06p45qcPeLmFYlZV0UCojXDEs7Qcyrt1PrAVi+sQb3vwWrvvH4hcZMiji4mo5ak8XzBlCOKsWar1LeIZ/uChsqI9RmywoMgDOsvFCbpA6l4uHqSN6emDXfJSH+ofU1BgyxpflFI1yLv9Nv8ntMZ/ZVXvrq8kTasRfBd6JsH6v",
    "pjm": "AAAAB3NzaC1yc2EAAAADAQABAAABAQC7qNIu1/Bx9a8Z9LPPp84bYvp1fp4P5e6AJy1rG93hLR8TDjLUQvXLZTRSOI+kDc7G36kOqtWbVPD7L81cV2bYpfUwcQH258q1w9U3b6m2JMzWex+9r7pO05ETXT1f1hTGqNlUoHDwdA82BMz6MXyi0H9I811M/QuL0FbrfQNUSQZsLZp92j7q55okgt9DqET4nOjksjeD8hREmIHlofX1TIxFNy0XyU4fYEFoIY7HX7/emNOG1+0YBIVewtUravkb6ogxwM/F1KdYaUn9ytljBzWtIqxAfE8eli6YxGAe6e8p7+g4454NeY8awo80HbWKckWjm41hxy8ql6mVUsSV",
    "lfc": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtB0rzbGeIVxxQnS+nswh7NMSx8sw6o4iMcFsWaA2kAte99xsTUkgUo48crZS+/OrAakmefxNM0SEJZMFfcogHH3BkkGs0UQTQNMRB5yhk+qlxdB6wzdc171c1MDQUO0RkVz5aY63UVKP2KhxDlDQjJnxqRyAatG/NyobKxWdgmacfpSdr56wDH3YGbLSkFU11onVclI8xg9TZ+dxUx9Vv78FNhl6yErtMGwADbMvqj5o17Uzaq9wnc+L6PjZq70TvX+q69QJtV5w1w7+lbRhJt0yuzs4dbAF7aNHMnHxVbGvE2uQzNw34+xboOGM9oCndJu5lAKmRbOZxB/fPLpQZwIDAQAB",
    "dcr": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDAqTqbl9cavQ0XP3EHWkAYWYQmxRXNB3ABxbK+n+Yujn+G1wH7bhh06tK8A2hQkF2OdM6Zl0XoRoCVC+KdGI26dMyAohTnkhC7wQ+uN8LRIZf5sx+AN+Ea7P9010+gA15kcZsvxOuz6Fu3QI1IwGHVYctHEz2bVS8EpbT9u95Cont/voxGx5vAYf2G7RrnT8cc5cT2Tz3FTF4W+LufBFtJ7+q6yIEgOH7tLKMIk6kRFKksW9HKQf3B8vXF0S5P2dNSNKaHjhRo0c8pQ0743EwJXSoMND5mWOSOcsNCpmjpgc0IsbvCJ7LTSPm5E0dacIk3Dt4+mMHayfU+6cw0SwUbAKX8xkwN59Uu68A2Nb1K9+RPm4OO/xXDsbxaZDxZy2wpvbr3bKZwac7bY+ERkWyt8NtIpvJaqwX9ZVEw4fOhckCEwdkvXX/YxSISOvbiw2HOj+aRZqSWsw2yp/y1Cci95aWbbZua9IkeJKKhunHV+ETjVi0xKFDbThFy8RsHN68=",
    "mpl": "AAAAB3NzaC1yc2EAAAADAQABAAABgQC4UEE2Bt03Hl5WvKQIqDCYb/DmBWGE1pLlbxWowICX90VsA/X+CdWcg+vlH8Ei4UIAPSU5MotNcvMHAyxaoGaORIIIkR9c8Mox9p9kXjAPYeP7LohvKq5BaPnULjq6JtaJvKfUO415FSxMPmwRsHwm915g3TIkNw6ucy5uS/UhUtN+VWeQC0MrzLymvgdmBBCmV1qlEc2c5h94Tl2GreQbmHkSbIcQj7Hussy1/xuUmJuvicMrXKVGSn3rJa4+RSdUgfnsk+9+ooSSONhhPOyVgWb1ZvYNpAqjorvz72dOueUSEJHjhOL86u3zVrwhNozFMbR4ZnMpRK3n+kvmKL+SUZRXSDXhBm+WNg67gpNbzmKiics49Q7uiSvtOFoPatOGh7K2q7J6jq5u6lugyTN8ZPTMxPtYcgcEKy2xYRxIpqiErmd2y3nzW1gLOdgKM0EVH8NyErpfpfB/Ra/f3FdZqApEMwSvlKI/sL4o+CndGqjHiWU6N2w3LKOePxRiSwU=",
    "salv": "AAAAB3NzaC1yc2EAAAADAQABAAACAQCbyiS2HSv6k4+vZNGVstTq2tbP71GQiQPEIBbgBgzVetnwsyHiZrlp3IH+6aqrhZKbdAz+lmu4wURZHzbmnhos61XenJl4Ny+0EnNIpF4XPv47NfZV/h9bHiCPWBRCxto6XWQWiI1ZaW6xgLplOVTxuHBz9bU4YNqs+ezdTqBOtuCDkHfTP4fOhthqNGi+LTRrAtd1o14Xz9jo049bJ9OEEWtQpqdXGc536vSBWLPii0aarqcKocXfIN2nqB0wXJ0QSGaOyD1wCV4SlmITZv7r8EowXTd4+9y3FmxtHcKwhn5JFh63/PffZOPhoJ07OF0Q48S6JKLlJ6UHB5r2CURmsNDHyiD0AG81OVHe4JBcgFIJC2bLMRNjL66Ei7zFT49mZMB+FICww8UaYbAm38c6NEDzYC+yL5ewlDlrtaXYq2x6HBe/i7Y2KJHXomxcsdfYPapk1eJMFcRL7RnEnXy1awTEGT+cAApm37vSC4ezloCvuKjCtJhKcwjtxLlzdDLOsItC5FuJ+uQcwaAQi6cCS5pGDW3dLkGh61iXlKP7nXRNttErkFnP7wolBXS893sXQPLsDUsEbP/pH8bWCKDRb+35Os+xq7Utx/lKJGRb2s5GoL9a5ipq6nzih9/9FrLU7JJGt8GTjJUYhG2r75qNlP0+TYC9h/8N/auMw0Lh1w==",
    "jov": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDOsiPn3+sdn0I9UH4naciMyJDgKakF5Ue6vHnQSotWCkNDrMkj1E4HkcgquxKMPk1efhIkjrTdrKVrIEWx4dqw2+TImeDMk1NS3lr+BptIpbo/2XQrMbw09eQ79O11lXHV9VFQGKL3n2NsKSscZQiihUlVVXM+5H1rOyKQIRQN4nv59fphwqGwlMjgA2zZpKCbbA8fzt/TczyTOP3K+orhtblTVagR6dtWxXbZkbO57xC060M82cFV/TBWulIdO9c517sbIahJWJ+Zqdm+Ed0ddJKgKXVamV15C33aMI/E6PZyBMzkRoZ2RMmds7N36kvLclbh8XKK8PkQ1t7mqJWAFU3fDnztPdm6cb2Oyi5WyUdKY5z2OXODrOKPVvnihpgPiqaYXCJGqMAf+gKSxXqJ6tQ0+SW1MwNAw3d47T7mOPxZPL2Cx6iCGl/agugRR1I2YsjWfCnXlAl/Vp55mmCKd+TnL5BzpHQft3rtnSgEYbxmffIxVIwPLDSnjhzfYY0=",
    "lgm": "AAAAB3NzaC1yc2EAAAADAQABAAABAQCvFbZOA0VWH5VU2HD4ujKiWaDNJPtq3QkMiT4mno9ZLXb8y01G23r+3BSyRhMU2O5WPQBcpGTOQ/ug3k8e9Bi6vVsGVJI3n+TZk20xJAo+N3N5BlJBhDCcW26TFxSGN9iY8lLg3pi0CEJtOpDcpiAbZsoKzyX5GiLyKm5Lz8cxRZEdFp3JB20e9vqPbpaX9fi/tXA2J7U7j0l2ZzMWcaIsGI8FJShfg7Bacw3YjzWqjRBYZb31sRvo4qYR01yUOThQfP+PeUHCDc24gE3GecZFWkJheuFtaX5qQVmVmMgx0SezRhyhX6t2fZj0dPgNAjsQ1pDd8HNiek078pEqxmGv",
    "jrv": "QQEOFhHZDpXvoFU5fwnyNjZTfP7bhMRSGBVahawQkSSpz5XalN3LEJh6Mf6Mcc25RZtqigqfGYmhXgShzOXlboZ+JYEPTFKWD2C5eDWFa6kf5Qj5EzlDw4YINSg3kSodWXEjf+M69gSoZ9AI9lS1pCJrxOlp8cWCZdESrv3itxnEkHD7jmmYBpXyNXxUZ/9QVus5iQJYvWsmuhptncIaVOYPewSZeMJWkR6j1mpmsXRoAydosq/cwzG9fUXYribTFvyMPhRPX9TgVKIODwqXnVtZ3Ig833nDRb5OVfU0SD8ulcuPqwTtIbfCB6go01nsPMm+Wbp+wHjibLGHTqs0dBOgNre4o49EhVVRzyRRjUfZLIKZyJ7BEpD2uIbC/rvbzZxM9+F2Eu4LAwDw6yg190srpeknlvTV1NzSdfSXVBgjmjlr+aXhdsKuMe2mp/VlEj2HXXd3UylQBDxjCzYyOvSjik=",
    "lds": "AAAAB3NzaC1yc2EAAAADAQABAAACAQClfL7B4x5jG3h3g1ZrqhI6Q9XvM4XrO4HO0g3KAaFgxGpPXW4oOpdazP77yKcmCTS5lY7IwF66+Rw83YfGnsU4Wz7R+N57oW9GZBDVf6RZMrhxkYFWtAdndjrlN4dMNjTa4VTYO/2wP1u7uA1wcqp/qU2aqeJ2CesoEFO1eFjxdndit1P+2H0CFgbLsslfFpLNNwXA4b6QNOAZwXnP1zpt4BM8/IQxE2cy6oXpfxaXcIqw8RFV1vYg9tA6r2bgg92OqQ9FEEbT9Xc0LacSocboHhi5aXj8qf//cLsgvNn2mdfzedfZlGsHUUTZFzKGoGwuZLXiLgLOACL1bb/mr10VPUMB5B7Bq/NRMhe0xEDHFz094ZHWTuSWzGNyOcN+2TXlj8rtgK+UMhd9LNjE3ki/UFWA5TS+/1vrmTISHQCRl/RrF+drNJ7hX3eY1GC0rHQJDV7Ht7i9bG4mg/Zoa8ryQ9XZXAvV59DNoLPt5jbYpCKSTPrAKPf65DjmDXuamkS+9EHSkwsTmvcf7U/8nvmkCunRc4Lu/UrpGHhsqPZmxBDou26IcijW1eguVRfnVgTcd8d1YR80wn4bJLZrVBgrn7CNaGwxnxRaAAG7GwtD9KcuS+odz04zp2qIz4jAj5aDWz36WxFWy149RjhWXcfaMX9N2S+vRirSNUhVPOty+w==",
    "bmg": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDgr1K80ce8WcM9/fx1RPPn1fkuAZTQfm0XZBfi8v3Llu5jWGPatTdW7/HXnDR5+/TOSyTLFpznb2D6q5XFcbZlTMuyUELDwCbIeOz9plI4wswk/PzUYJA/3z6uS85MeYK5lDEmwDmtgyBPFp6HDL8UAzo3DSodH2P4/n/VoR9WCBlofzJbT6DbjTH0hOu4Uu5DGwV4ssznfwVpOALicz2N4LiR3iXZ3DRZz1j/jsMT3UIgo6vO/SMvdIiEN/arhc4f02W35OfxkHGojPadRg6dwN1EA+Z00aaUSdEIG3yaFY890r5l3XbKXHkllRNXOuSdmyX5vmBx1pn7NjkMcaavIMztggbRdBGdfrrVxgbPhocJ1eM3VWmleXatPsFTllGF8hvoh/StwmooQYd9EOU9mvef1UDWiGAhIOW29C4TKHJdgsB9HNDydgnb1FgzS2U6LqcA3O4rQHJpf5q+0AxBKHYOZqsBI5Mk3ErAx3U1hGbT1EhDmws15LQ/aak4y38="
    }

    @classmethod
    def get_key(cls, id: str):

        print (id)
        k = cls.pubkey_dictionary.get(id)
        print (('ssh-rsa ' + k).encode('ascii'))

        if k is None:
            print(f'Error: Could not get key for id \'{id}\'')
            exit(-1)

        return serialization.load_ssh_public_key(
            ('ssh-rsa ' + k).encode('ascii'),
            backend=default_backend()
        )