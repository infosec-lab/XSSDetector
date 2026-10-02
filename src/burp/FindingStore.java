package burp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Thread-safe, observable store of live findings. The scanner threads and the
 * proxy listener push findings here; the Live Results UI observes it and
 * refreshes on the Swing thread. De-duplicated by {@link XssFinding#dedupKey()},
 * with CONFIRMED upgrading an earlier REFLECTED entry for the same spot.
 */
public final class FindingStore {

    public interface Listener {
        void onFindingsChanged();
    }

    private static final FindingStore INSTANCE = new FindingStore();

    public static FindingStore get() {
        return INSTANCE;
    }

    private final Map<String, XssFinding> byKey = new LinkedHashMap<>();
    private final List<Listener> listeners = new ArrayList<>();

    private FindingStore() {
    }

    /** Add a finding; returns true if the view changed (new or upgraded). */
    public synchronized boolean add(XssFinding f) {
        if (f == null) {
            return false;
        }
        boolean changed;
        synchronized (byKey) {
            String key = f.dedupKey();
            XssFinding existing = byKey.get(key);
            if (existing == null) {
                byKey.put(key, f);
                changed = true;
            } else if (XssFinding.STATUS_CONFIRMED.equals(f.status)
                    && !XssFinding.STATUS_CONFIRMED.equals(existing.status)) {
                byKey.put(key, f); // upgrade reflected -> confirmed
                changed = true;
            } else {
                changed = false;
            }
        }
        if (changed) {
            notifyListeners();
        }
        return changed;
    }

    public List<XssFinding> snapshot() {
        synchronized (byKey) {
            return new ArrayList<>(byKey.values());
        }
    }

    public int size() {
        synchronized (byKey) {
            return byKey.size();
        }
    }

    public void clear() {
        synchronized (byKey) {
            byKey.clear();
        }
        notifyListeners();
    }

    public void addListener(Listener l) {
        synchronized (listeners) {
            if (!listeners.contains(l)) {
                listeners.add(l);
            }
        }
    }

    public void removeListener(Listener l) {
        synchronized (listeners) {
            listeners.remove(l);
        }
    }

    private void notifyListeners() {
        List<Listener> copy;
        synchronized (listeners) {
            copy = new ArrayList<>(listeners);
        }
        for (Listener l : copy) {
            try {
                l.onFindingsChanged();
            } catch (Exception ignored) {
                // a bad listener must not break detection
            }
        }
    }
}
