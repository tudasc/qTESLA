package com.example.qteslap3c;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final Button p3_start_button = findViewById(R.id.btn_start_p3);

        p3_start_button.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                //EditText tv = findViewById(R.id.editText);

                EditText noruns = findViewById((R.id.edit_its));
                EditText nosignsperrun = findViewById((R.id.edit_signs));
                EditText nothreads = findViewById(R.id.edit_threads);
                EditText et_rsabitlen = findViewById(R.id.edit_bitlen );

                CheckBox cb_crsa = findViewById (R.id.cb_crsa);
                CheckBox cb_qtesla = findViewById (R.id.cb_cqtesla);
                CheckBox cb_crsakeygen = findViewById (R.id.cb_cgenrsa);
                CheckBox cb_cecdsa = findViewById (R.id.cb_cecdsa);

                int bitflags = 0;
                int rsabitlen = 1024;

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


                // Check which value the user deployed for rsa-bitlen
                try {
                    rsabitlen = Integer.parseInt(et_rsabitlen.getText().toString());
                }
                catch (NumberFormatException e)
                {
                    rsabitlen = 1024;
                }

                // Check if qtesla should be tested
                if(cb_qtesla.isChecked()) {
                    bitflags |= (1 << 0);
                }

                // Check if RSA should be tested
                if(cb_crsa.isChecked()) {
                    bitflags |= (1 << 1);
                }

                // Check if RSA-Key should be generated or red
                if(cb_crsakeygen.isChecked()) {
                    bitflags |= (1 << 2);
                }

                // Check if ECDSA should be tested
                if(cb_cecdsa.isChecked()) {
                    bitflags |= (1 << 3);
                }

                // Check if user passed a number of threads to use
                int numthreads;
                // Check if user deployed a value for the number of runs
                try {
                    numthreads = Integer.parseInt(nothreads.getText().toString());
                }
                catch (NumberFormatException e)
                {
                    numthreads = 1;
                }

                EditText tv = findViewById(R.id.sample_text);
                try {
                    // Example of a call to a native method
                    //tv.setText ( Integer.toString(bitflags) );

                    tv.setText(stringFromJNI(inoruns, inosignsperrun, numthreads, bitflags, rsabitlen ));
                }

                catch (Exception e) {
                    tv.setText(e.getMessage());

                }
            }
        });




    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI(int runs, int signsperrun, int threadstouse, int biflag, int rsabitlen);
}
