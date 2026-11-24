from decimal import Decimal, ROUND_HALF_UP

from django import template


register = template.Library()


@register.filter
def fcfa(value):
    if value in (None, ""):
        value = 0
    amount = Decimal(str(value)).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    integer = f"{int(amount):,}".replace(",", " ")
    return f"{integer} Fr"
