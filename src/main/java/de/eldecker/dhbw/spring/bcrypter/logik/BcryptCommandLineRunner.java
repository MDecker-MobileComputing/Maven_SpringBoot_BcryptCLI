package de.eldecker.dhbw.spring.bcrypter.logik;

import static org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.BCryptVersion.$2B;

import java.security.SecureRandom;
import java.util.Optional;
import java.util.Scanner;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * In der GitHub-Actions-Pipeline wird der Build mit dem Profil {@code non-interaktiv} durchgeführt,
 * damit diese Klasse nicht ausgeführt wird (sie wartet auf eine Nutzereingabe, die bei einer
 * Pipeline-Ausführung nicht möglich ist).
 */
@Service
@Profile("!non-interaktiv")
public class BcryptCommandLineRunner implements CommandLineRunner {

    /** 
     * Sicherer Zufallsgenerator für Salt-Erzeugung. Der Salt fließt in
     * den Hash-Algorithmus als Input ein und ist auch erzeugten Hash-Wert
     * enthalten; er soll verhindern, dass sog. "Rainbow Tables" zum 
     * Einsatz kommen.
     */
    final SecureRandom _zufallsgenerator = new SecureRandom();

    /** Text-Scanner für Einlesen Nutzereingaben von STDIN. */
    final Scanner _scanner = new Scanner( System.in );


    /**
     * Diese Methode wird beim Programmstart automatisch aufgerufen.
     * Wenn diese Methode beendet ist, dann wird das Programm beendet.
     *
     * @param args Wird nicht ausgewertet
     */
    public void run( String... args ) throws Exception {

        final Optional<String> passwortOptional = passwortEinlesen();
        if ( passwortOptional.isEmpty() ) { return; }

        final String passwort = passwortOptional.get();

        for ( int i = 4; i < 31; i++ ) {

            verhashen( passwort, i );
        }
    }


    /**
     * Passwort mit Bcrypt verhashen und Ergebnis und Laufzeit auf Konsole ausgeben.
     * <br><br>
     *
     * Für die Messung der Laufzeit wird die Methode {@code System.nanoTime()} statt
     * {@code currentTimeMillis()} verwendet, weil letztere falsche Ergebnisse liefert,
     * wenn die Systemzeit während der Zeitmessung angepasst wird.
     * <br><br>
     *
     * <b>Beispielausgabe:</b>
     * <pre>
     * Hashwert: $2b$10$SSNjbgJFzz239WHLCuOURew3/sft2QZVEWqbJfVCSSAAg8ZskjTxi
     * Rechenzeit: 61 ms
     * </pre>
     *
     * @param passwort Passwort, das verhasht werden soll
     *
     * @param kostenFaktor Kostenfaktor für Bcrypt-Algorithmus, muss zwischen {@code 4} und 
     *                     {@code 31} liegen;
     *                     je höher der Wert, desto länger dauert die Berechnung.
     *                     Die Anzahl der Runden für die Verhashung wird mit  
     *                     {@code 2^kostenFaktor} berechnet, also für {@code 12} bspw. 
     *                     {4.096} Runden. 
     */
    private void verhashen( String passwort, int kostenFaktor ) {

        if ( kostenFaktor < 4 || kostenFaktor > 31 ) {

            System.out.println( "Kostenfaktor " + kostenFaktor + " liegt nicht zwischen 4 und 31." );
            return;
        }

        final BCryptPasswordEncoder bcryptEncoder =
                new BCryptPasswordEncoder( $2B, kostenFaktor, _zufallsgenerator );

        final long   zeitpunktStart = System.nanoTime();
        final String hashwert       = bcryptEncoder.encode( passwort ); // eigentliche Verhashung
        final long   zeitpunktEnde  = System.nanoTime();

        final long millisekunden = ( zeitpunktEnde - zeitpunktStart ) / 1_000_000;

        System.out.println( "\nHashwert: " + hashwert );
        System.out.println( "Rechenzeit: " + millisekunden + " ms" );
    }


    /**
     * Liest Passwort von der Tastatur ein.
     *
     * @return Optional ist leer, wenn Nutzer leeren String eingegeben hat; ansonsten
     *         ist das "getrimmte" Passwort enthalten.
     */
    private Optional<String> passwortEinlesen() {

        System.out.print ( "\nPasswort zum Verhaschen mit Bcrypt eingeben > " );
        String nutzereingabeString1 = _scanner.nextLine();

        nutzereingabeString1 = nutzereingabeString1.trim();
        if ( nutzereingabeString1.isBlank() ) {

            System.out.println( "FEHLER: Leeres Passwort eingegeben" );
            return Optional.empty();

        } else {

            final int anzZeichen = nutzereingabeString1.length();
            System.out.println( "\nAnzahl Zeichen von Passwort: " + anzZeichen );

            return Optional.of( nutzereingabeString1 );
        }
    }

}
