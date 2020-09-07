package com.example.qteslajava;

import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;


import qTESLA.Logger;
import qTESLA.Test;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        /*FloatingActionButton fab = findViewById(R.id.editText);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });*/

        final Button start_button = findViewById(R.id.button);

        start_button.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                EditText tv = findViewById(R.id.editText);

                EditText noruns = findViewById((R.id.editText2));

                EditText nosignsperrun = findViewById((R.id.editText3));

                EditText nothreads = findViewById((R.id.editText4));

                CheckBox cb_crsa = findViewById (R.id.cb_crsa);
                CheckBox cb_qtesla = findViewById (R.id.cb_cqtesla);
                CheckBox cb_crsakeygen = findViewById (R.id.cb_cgenrsa);
                CheckBox cb_cecdsa = findViewById (R.id.cb_cecdsa);
                EditText et_rsabitlen = findViewById (R.id.edit_bitlen);
                int bitflags = 0;
                int rsabitlen = 1024;

                // Check which value the user deployed for rsa-bitlen
                try {
                    rsabitlen = Integer.parseInt(et_rsabitlen.getText().toString());
                    Logger.rsa_bitlen = rsabitlen;
                }
                catch (NumberFormatException e)
                {
                    rsabitlen = 1024;
                    Logger.rsa_bitlen = rsabitlen;
                }

                // Check if qtesla should be tested
                if(cb_qtesla.isChecked()) {
                    bitflags |= (1 << 0);
                    Logger.test_qtesla = true;
                }
                else {
                    Logger.test_qtesla = false;
                }

                // Check if RSA should be tested
                if(cb_crsa.isChecked()) {
                    bitflags |= (1 << 1);
                    Logger.test_rsa = true;
                }
                else {
                    Logger.test_rsa = false;
                }

                // Check if RSA-Key should be generated or red
                if(cb_crsakeygen.isChecked()) {
                    bitflags |= (1 << 2);
                }

                // Check if ECDSA should be tested
                if(cb_cecdsa.isChecked()) {
                    Logger.test_ecdsa = true;
                    bitflags |= (1 << 3);
                }
                else {
                    Logger.test_ecdsa = false;
                }

                int inoruns;

                // Check if user deployed a value for the number of runs
                try {
                    inoruns = Integer.parseInt(noruns.getText().toString());
                }
                catch (NumberFormatException e)
                {
                    inoruns = 15;
                }


                // Check if user passed a number of signs per run
                int inosignsperrun;
                // Check if user deployed a value for the number of runs
                try {
                    inosignsperrun = Integer.parseInt(nosignsperrun.getText().toString());
                }
                catch (NumberFormatException e)
                {
                    inosignsperrun = 1;
                }


                // Get number of threads to use
                // Check if user deployed a value for the number of runs
                try {
                    Logger.no_of_threads = Integer.parseInt(nothreads.getText().toString());
                }
                catch (NumberFormatException e)
                {
                    Logger.no_of_threads = 1;
                }

                try {
                    Test.mainTest(inoruns, inosignsperrun);
                    tv.setText(Logger.popMessage());
                }

                catch (Exception e) {
                    tv.setText(e.getMessage());

                }
            }
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
