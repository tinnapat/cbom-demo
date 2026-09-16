package com.tinnapat.demo.cbom;

import java.util.ArrayList;
import java.util.List;

/**
 * Collects runtime evidence while the demos execute.
 *
 * <p>This is the dimension a static CBOM cannot supply: which provider actually served an
 * algorithm, and whether the JVM still permits it at all. Comparing this log against a scanner's
 * {@code cbom.json} is the point of the whole repository.
 */
public final class Evidence {

	public record Entry(String ruleGroup, String algorithm, String provider, String detail, boolean executed) {
	}

	private final List<Entry> entries = new ArrayList<>();
	private String currentGroup = "";

	void group(String ruleGroup) {
		this.currentGroup = ruleGroup;
	}

	/** Records an algorithm that ran successfully. */
	public void ok(String algorithm, String provider, String detail) {
		entries.add(new Entry(currentGroup, algorithm, provider, detail, true));
	}

	/** Records an algorithm whose call site exists but that the runtime refused. */
	public void unavailable(String algorithm, String reason) {
		entries.add(new Entry(currentGroup, algorithm, "-", reason, false));
	}

	public List<Entry> entries() {
		return List.copyOf(entries);
	}

	public long executedCount() {
		return entries.stream().filter(Entry::executed).count();
	}
}
