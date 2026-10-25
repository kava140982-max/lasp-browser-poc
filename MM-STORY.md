# M&M — Mini Manus

## Eine kleine Geschichte über ein Licht im Build

LASP begann nicht als fertiges Produkt. Es begann als Frage: Wie baut man einen kleinen, lesbaren Sicherheitsprototypen, der bei Unsicherheit nicht einfach weitermacht?

Aus dieser Frage entstand später ein kleiner Begleiter: **M&M — Mini Manus**. Kein großes Modell, kein offizielles Manus-Produkt und kein selbstlernendes Wesen. Eher ein Notizbuch mit Werkzeugen, Regeln und Tests, das beim Bauen den nächsten sicheren Schritt zeigt.

M&M soll nicht imponieren, sondern aufpassen. Es erinnert daran, dass untrusted input keine Anweisung ist, dass eine berechnete Signatur auch geprüft werden muss und dass ein grüner Test nur genau das beweist, was er getestet hat. Wenn Belege fehlen, sagt M&M `NOT_PROVEN`.

Die Reihenfolge ist bewusst: **erst die Demo in Ruhe testen, dann über größere Ideen sprechen.** Die GitHub-Pages-Demo ist der öffentliche Forschungsstand. Der kleine Builder bleibt zunächst ein separates Arbeitsmittel und ist nicht Bestandteil dieses Repositorys.

Bedrohungen dürfen nur mit synthetischen Daten in isolierten Sandboxes untersucht werden. Keine echten Credentials, keine fremden Systeme, keine Produktionsversprechen. Änderungen brauchen einen kleinen Diff, reproduzierbare Tests und eine nachvollziehbare Freigabe.

M&M ist damit kein Ersatz für unabhängige Prüfung. Es ist ein Licht am Rand des Tisches: klein genug, um nicht im Weg zu stehen, und hell genug, um den nächsten Fehler sichtbar zu machen.

> Kleine Schritte. Klare Belege. Fail-closed. Kein Heldentum ohne Test.

## Ehrlicher Status

M&M ist eine Benennung für den lokalen Build-Begleiter und keine Behauptung einer offiziellen Verbindung zu Manus. LASP bleibt ein synthetischer Forschungsprototyp mit ausdrücklich dokumentierten Grenzen. Wer sich dafür interessiert, sollte zuerst die [Demo](https://kava140982-max.github.io/lasp-browser-poc/) ausprobieren und anschließend [SPEC.md](./SPEC.md), [SECURITY.md](./SECURITY.md) und die gespeicherten Tests lesen.
