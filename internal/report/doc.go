// Package report turns tables and documents into output: a generic Table with
// writers for text, CSV, JSON, NDJSON, Markdown and HTML, a self-contained
// HTML document builder, and a few formatting helpers shared by the CLI.
//
// # Tables
//
// A Table is a list of typed Columns and rows of loosely typed cells (see
// Table for the accepted cell types and the meaning of a missing value).
// Write renders it in a Format; WriteSections renders several.
//
// Common rules: all untrusted text is sanitised for the destination
// (invalid UTF-8 and control characters, ESC included, become U+FFFD, so a
// capture cannot inject terminal escapes); CSV, JSON and NDJSON carry every
// column while table, Markdown and HTML hide Extra columns unless
// Options.Extra is set; output is deterministic; large tables are streamed in
// chunks and rendering time is linear in the size of the table.
//
// # HTML documents
//
// WriteHTML renders a Document built from Blocks (Heading, Paragraph,
// KeyValues, TableBlock, Pre, Details, Badges, SVG, RawHTML) into one file
// with inline CSS and one inline script (column sort, text filter). Only
// SVG.Markup and RawHTML.HTML are written verbatim; everything else is escaped.
//
// CSS classes (a stable contract for custom RawHTML and for tests; all are
// prefixed "sc-"):
//
//	sc-doc, sc-header, sc-title, sc-subtitle, sc-generated, sc-main   page frame
//	sc-h, sc-h1 .. sc-h6                                              headings
//	sc-p                                                              paragraph
//	sc-kv, sc-card, sc-k, sc-v                                        key/value cards
//	sc-tablebox, sc-tools, sc-filter, sc-count, sc-scroll             interactive table wrapper
//	sc-table, sc-caption, sc-num                                      table, caption, right aligned cell
//	sc-good, sc-warn, sc-bad, sc-dim                                  Style (cells, cards, badges)
//	sc-pre                                                            preformatted text
//	sc-details, sc-summary, sc-body                                   collapsible group
//	sc-badges, sc-badge                                               badges
//	sc-fig, sc-figcap, sc-raw                                         SVG figure, raw markup wrapper
//	sc-section                                                        WriteSections html section
package report
