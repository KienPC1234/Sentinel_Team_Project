"""Shared pagination helpers for manual APIView list endpoints."""
from math import ceil
from typing import Any, Callable, Dict, List, Optional

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


def _as_int(value: Any, default: int, minimum: int = 1, maximum: Optional[int] = None) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    number = max(minimum, number)
    if maximum is not None:
        number = min(number, maximum)
    return number


def paginate_queryset(
    request,
    queryset,
    serialize: Callable[[List[Any]], List[Any]],
    *,
    default_page_size: int = DEFAULT_PAGE_SIZE,
    max_page_size: int = MAX_PAGE_SIZE,
    page_param: str = 'page',
    page_size_param: str = 'page_size',
) -> Dict[str, Any]:
    """Slice a queryset/list and return the standard page envelope.

    ``serialize`` receives the already-sliced list so callers can keep their
    existing dict-building code without materialising the whole table.
    """
    params = getattr(request, 'query_params', None) or getattr(request, 'GET', {})
    page = _as_int(params.get(page_param), 1)
    page_size = _as_int(
        params.get(page_size_param),
        default_page_size,
        maximum=max_page_size,
    )
    total = queryset.count() if hasattr(queryset, 'count') else len(queryset)
    offset = (page - 1) * page_size
    items = list(queryset[offset:offset + page_size])
    pages = max(1, ceil(total / page_size)) if total else 1

    def page_url(target: int) -> str:
        mutable = params.copy()
        mutable[page_param] = str(target)
        return f"{getattr(request, 'path', '')}?{mutable.urlencode()}"

    return {
        'results': serialize(items),
        'count': total,
        'page': page,
        'page_size': page_size,
        'pages': pages,
        'next': page_url(page + 1) if page < pages else None,
        'previous': page_url(page - 1) if page > 1 else None,
    }
